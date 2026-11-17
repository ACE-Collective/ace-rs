//! PLAN.md 7.4: the DNS module against ace3's reference dumps, with the answers ace3 got from
//! tools/ace3/dumps/fake_dns.py replayed from the recording beside each dump. Nothing reaches a
//! real resolver. Every difference is listed and explained in differences.md, next to this file.

use std::path::Path;

use ace_mod_dns::FqdnAnalyzer;
use ace_results::ObservableKind;
use ace_testkit::Harness;
use ace_testkit::dns::DnsReplay;
use ace_testkit::reference::{Dump, ListedDifferences, diff, dumps_dir, normal_form};
use serde_json::json;

#[tokio::test]
async fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = Vec::new();
    let dumps = Dump::all("fqdn_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 7, "one dump of each outcome");
    for dump in dumps {
        let recording = dumps_dir().join(format!("{}.dns.json", dump.name));
        let replay = DnsReplay::start(&[recording.as_path()])
            .await
            .expect("the recording loads");
        let harness = Harness::<FqdnAnalyzer>::with_settings(json!({
            "nameservers": [replay.addr().to_string()],
        }))
        .expect("harness");
        let input = &dump.value["input"]["observable"];
        assert_eq!(input["type"], "fqdn");
        let value = input["value"].as_str().expect("a value");
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::Fqdn, value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        assert!(
            replay.unmatched().is_empty(),
            "{}: queries nothing was recorded for: {:?}",
            dump.name,
            replay.unmatched()
        );
        // the same queries, in the same order
        let recorded: Vec<String> = serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(&recording).expect("reads"),
        )
        .expect("JSON")["exchanges"]
            .as_array()
            .expect("exchanges")
            .iter()
            .map(|e| {
                format!(
                    "{} {}",
                    e["name"].as_str().unwrap_or_default(),
                    e["type"].as_str().unwrap_or_default()
                )
            })
            .collect();
        assert_eq!(replay.asked(), recorded, "{}", dump.name);
        if dump.short_name() == "fqdn_example.com" {
            ace_testkit::check_view_fixture("dns_fqdn_example_com", &outcome);
        }
        // a failed lookup's reason names the nameserver, as dnspython's does: ace3's was its fake,
        // at 127.0.0.1@5353, and this test's is the replay, on a port of its own. The replay's
        // address is put as ace3's, and the rest of the text is compared as it is.
        let mut ours = normal_form(&outcome);
        if let Some(error) = ours["error"].as_str() {
            let addr = replay.addr();
            ours["error"] = json!(error.replace(
                &format!("Do53:{}@{}", addr.ip(), addr.port()),
                "Do53:127.0.0.1@5353"
            ));
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(&dump.normal_form("FQDNAnalysis"), &ours),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
