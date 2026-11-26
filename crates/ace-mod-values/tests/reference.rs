//! PLAN.md 7.5 batch 3: the modules that read an observable's value against ace3's reference dumps,
//! made from the observables `tools/ace3/dumps/make-dumps`' `values` runs name. Every difference is
//! listed and explained in differences.md, next to this file.
//!
//! ace3's `network_identifier` read `tools/ace3/dumps/fixtures/values/local_networks.csv`, except
//! for `default_file`, which had ace3's own file, a header alone; here those rows are its settings.
//! ace3's `protected_url_analyzer` followed its 1drv.ms links through the recording in
//! `fixtures/values/one_drive`; here `protected_url_one_drive` follows them through the same
//! recording, and the parser module leaves them alone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ace_mod_values::protected::{self, Hop};
use ace_mod_values::{
    CommandLineAnalyzer, EmailAddressFqdnAnalyzer, FileLocationAnalyzer, FilePathAnalyzer,
    IdnaAnalyzer, NetworkIdentifier, OneDriveUrlAnalyzer, ParseUrlAnalyzer, ProtectedUrlAnalyzer,
};
use ace_results::{ObservableKind, ObservableRef, Relationship, RelationshipKind};
use ace_sdk::{Observable, Outcome, Parser};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/values")
}

/// The dump's observable, with its directives and relationships.
fn input<M: Parser>(harness: &Harness<M>, dump: &Dump) -> Observable {
    let input = &dump.value["input"];
    let kind: ObservableKind = input["observable"]["type"]
        .as_str()
        .expect("a type")
        .parse()
        .expect("a kind");
    let mut observable = harness.observable(
        kind,
        input["observable"]["value"].as_str().expect("a value"),
    );
    for directive in input["directives"].as_array().into_iter().flatten() {
        observable = observable.with_directive(directive.as_str().expect("a directive"));
    }
    for r in input["relationships"].as_array().into_iter().flatten() {
        let kind: RelationshipKind =
            serde_json::from_value(r["type"].clone()).expect("a relationship kind");
        let target_kind: ObservableKind = r["target"]["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a kind");
        let target =
            ObservableRef::new(target_kind, r["target"]["value"].as_str().expect("a value"));
        observable = observable.with_relationship(Relationship::new(kind, target));
    }
    observable
}

type Compared = Vec<(String, Vec<Difference>)>;

fn compare<M: Parser>(
    module: &str,
    class: &str,
    settings: impl Fn(&Dump) -> Value,
    view: Option<(&str, &str)>,
) -> Compared {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        let harness = Harness::<M>::with_settings(settings(&dump)).expect("harness");
        let observable = input(&harness, &dump);
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if let Some((name, fixture)) = view
            && dump.short_name() == name
        {
            ace_testkit::check_view_fixture(fixture, &outcome);
        }
        let differences = diff(&dump.normal_form(class), &normal_form(&outcome));
        compared.push((format!("{module}/{}", dump.short_name()), differences));
    }
    compared
}

/// The rows of the CSV ace3's network identifier read, as settings.
fn networks(dump: &Dump) -> Value {
    if dump.short_name() == "default_file" {
        return json!({"networks": []});
    }
    let text = std::fs::read_to_string(fixtures().join("local_networks.csv")).expect("reads");
    let (rows, error) = ace_pycompat::csv::read_all(&text);
    assert!(error.is_none(), "the CSV reads");
    assert_eq!(rows[0], ["Indicator", "Indicator_Type"]);
    let networks: Vec<Value> = rows[1..]
        .iter()
        .map(|row| json!({"cidr": row[0], "name": row[1]}))
        .collect();
    json!({"networks": networks})
}

/// What the recording answers each URL with.
fn one_drive_recording() -> BTreeMap<String, Hop> {
    let text = std::fs::read_to_string(fixtures().join("one_drive/http.json")).expect("reads");
    let recording: Value = serde_json::from_str(&text).expect("JSON");
    recording["exchanges"]
        .as_array()
        .expect("exchanges")
        .iter()
        .map(|e| {
            let location = e["response_headers"]
                .as_object()
                .and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")))
                .and_then(|(_, v)| v.as_str())
                .map(str::to_owned);
            let status = u16::try_from(e["status"].as_u64().expect("a status")).expect("a status");
            (
                e["url"].as_str().expect("a url").to_owned(),
                (status, location),
            )
        })
        .collect()
}

/// The protected URL dumps: the parser module, or for a 1drv.ms link the lookup module's result
/// from the same recording ace3 was answered from.
async fn compare_protected() -> Compared {
    let recording = one_drive_recording();
    let hosts = protected::OneDriveSettings::default().redirect_hosts;
    let mut compared = Vec::new();
    for dump in Dump::all("protected_url_analyzer").expect("the dumps read") {
        let harness = Harness::<ProtectedUrlAnalyzer>::new().expect("harness");
        let observable = input(&harness, &dump);
        let parsed = harness
            .run_parser(observable.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let ace_rs = if protected::is_one_drive_link(&observable.value) {
            assert!(
                matches!(parsed, Outcome::Skipped(_)),
                "{}: the parser leaves a 1drv.ms link to the lookup",
                dump.name
            );
            let final_url = protected::follow(&observable.value, &hosts, |url| {
                let answer = recording
                    .get(&url)
                    .cloned()
                    .ok_or_else(|| format!("nothing recorded for GET {url}"));
                async move { answer }
            })
            .await;
            let outcome = Outcome::Done(protected::one_drive_result(
                &observable,
                final_url.as_deref(),
            ));
            if dump.short_name() == "one_drive" {
                ace_testkit::check_view_fixture("protected_url_one_drive", &outcome);
            }
            normal_form(&outcome)
        } else {
            if dump.short_name() == "safelinks" {
                ace_testkit::check_view_fixture("protected_url_safelinks", &parsed);
            }
            normal_form(&parsed)
        };
        let differences = diff(&dump.normal_form("ProtectedURLAnalysis"), &ace_rs);
        compared.push((
            format!("protected_url_analyzer/{}", dump.short_name()),
            differences,
        ));
    }
    compared
}

#[tokio::test]
async fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let none = |_: &Dump| Value::Null;
    let mut compared = compare::<CommandLineAnalyzer>(
        "command_line_analyzer",
        "CommandLineAnalysis",
        none,
        Some(("encoded_short", "command_line_encoded_short")),
    );
    compared.extend(compare::<FilePathAnalyzer>(
        "file_path_analysis",
        "FilePathAnalysis",
        none,
        Some(("user_path", "file_path_user_path")),
    ));
    compared.extend(compare::<FileLocationAnalyzer>(
        "file_location_analysis",
        "FileLocationAnalysis",
        none,
        Some(("windows", "file_location_windows")),
    ));
    compared.extend(compare::<NetworkIdentifier>(
        "network_identifier",
        "NetworkIdentifierAnalysis",
        networks,
        Some(("two_networks", "network_two_networks")),
    ));
    compared.extend(compare::<ParseUrlAnalyzer>(
        "parse_url",
        "ParseURLAnalysis",
        none,
        Some(("full", "parse_url_full")),
    ));
    compared.extend(compare::<IdnaAnalyzer>(
        "idna_analyzer",
        "IDNAAnalysis",
        none,
        Some(("unicode", "idna_unicode")),
    ));
    compared.extend(compare::<EmailAddressFqdnAnalyzer>(
        "email_address_fqdn_analyzer",
        "EmailAddressFQDNAnalysis",
        none,
        Some(("plain", "email_address_fqdn_plain")),
    ));
    compared.extend(compare_protected().await);
    assert!(
        compared.len() >= 80,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

/// The lookup module asks nothing for a URL that isn't a 1drv.ms link.
#[tokio::test]
async fn the_one_drive_lookup_skips_other_urls() {
    let harness = Harness::<OneDriveUrlAnalyzer>::new().expect("harness");
    for url in [
        "https://www.example.com/",
        "https://evil1drv.ms.example.com/x",
    ] {
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::Url, url))
            .await
            .expect("runs");
        assert!(matches!(outcome, Outcome::Skipped(_)), "{url}");
    }
}

/// Redirects are followed only on the hosts the settings name, and a link that leaves them, or
/// goes on too long, counts as one that couldn't be followed.
#[tokio::test]
async fn redirects_stay_on_microsofts_hosts() {
    let hosts = protected::OneDriveSettings::default().redirect_hosts;
    let to = |location: &str| Ok((302, Some(location.to_owned())));
    let away = protected::follow("https://1drv.ms/x", &hosts, |url| {
        let answer = match url.as_str() {
            "https://1drv.ms/x" => to("https://evil.example.com/?resid=1&authkey=2"),
            _ => Err(format!("asked for {url}")),
        };
        async move { answer }
    })
    .await;
    assert_eq!(away, None);
    let relative = protected::follow("https://1drv.ms/x", &hosts, |url| {
        let answer = match url.as_str() {
            "https://1drv.ms/x" => to("/y?resid=1&authkey=2"),
            "https://1drv.ms/y?resid=1&authkey=2" => Ok((200, None)),
            _ => Err(format!("asked for {url}")),
        };
        async move { answer }
    })
    .await;
    assert_eq!(
        relative.as_deref(),
        Some("https://1drv.ms/y?resid=1&authkey=2")
    );
    let endless = protected::follow("https://1drv.ms/x", &hosts, |_| async {
        to("https://1drv.ms/x")
    })
    .await;
    assert_eq!(endless, None);
    // ace3 would ask a host that only ends in 1drv.ms; this asks nothing and records the link
    assert!(protected::is_one_drive_link("https://evil1drv.ms/x"));
    let lookalike = protected::follow("https://evil1drv.ms/x", &hosts, |url| async move {
        Err(format!("asked for {url}"))
    })
    .await;
    assert_eq!(lookalike, None);
    let link = ace_sdk::Observable::new(ObservableKind::Url, "https://evil1drv.ms/x");
    let result = protected::one_drive_result(&link, None);
    assert_eq!(
        result.details.protection_type.as_deref(),
        Some("unprotected")
    );
    assert!(result.observables.is_empty());
}

/// ace3's root takes at most 500 file observables, so the module writes no more payloads' files
/// than that, and lists the rest.
#[test]
fn a_command_line_writes_at_most_500_payload_files() {
    let harness = Harness::<CommandLineAnalyzer>::new().expect("harness");
    let value = "pwsh -e QUJD ".repeat(600);
    let outcome = harness
        .run_parser(harness.observable(ObservableKind::CommandLine, &value))
        .expect("runs");
    let Outcome::Done(result) = outcome else {
        panic!("a result");
    };
    assert_eq!(result.files.len(), 500);
    assert_eq!(result.details.base64_payloads.len(), 600);
    assert_eq!(
        result.details.base64_payloads[599].file_path,
        "command_line_base64_payload_598.bin"
    );
}

/// Only a Proofpoint URL has urlfinderlib describe text, so only its task reads libmagic's
/// database: the module reads none of it at `init` or for any other URL, and with the database
/// missing a Proofpoint URL fails, naming it.
#[test]
fn only_a_proofpoint_url_reads_libmagics_database() {
    let database = std::fs::metadata(ace_urlfinder::magic::DATABASE)
        .expect("the database")
        .len();
    let safelinks = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.com%2Fpage&data=xyz";
    let proofpoint =
        "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example.com_path&d=DwMF&c=x";
    let run = |url: &str| {
        ace_testkit::bytes_read_by(|| {
            let harness = Harness::<ProtectedUrlAnalyzer>::new().expect("harness");
            harness.run_parser(harness.observable(ObservableKind::Url, url))
        })
    };
    let extracted = |outcome: Result<Outcome<_>, _>| match outcome {
        Ok(Outcome::Done(result)) => {
            let result: ace_results::ResultEnvelope<
                ace_results::types::values::ProtectedUrlAnalysis,
            > = result;
            result.details.extracted_url
        }
        other => panic!("{other:?}"),
    };

    let (outcome, read) = run(safelinks);
    assert_eq!(
        extracted(outcome).as_deref(),
        Some("https://evil.example.com/page")
    );
    assert!(read < database / 10, "{read} bytes read for {safelinks}");
    // what the count would see of a read
    let (outcome, read) = run(proofpoint);
    assert_eq!(
        extracted(outcome).as_deref(),
        Some("https://evil.example.com/path")
    );
    assert!(read >= database, "{read} bytes read for {proofpoint}");

    let missing = Path::new("/nonexistent/magic.mgc");
    let harness = Harness::<ProtectedUrlAnalyzer>::new()
        .expect("harness")
        .with_module(ProtectedUrlAnalyzer::with_database(missing));
    let outcome = harness.run_parser(harness.observable(ObservableKind::Url, safelinks));
    assert!(extracted(outcome).is_some());
    match harness.run_parser(harness.observable(ObservableKind::Url, proofpoint)) {
        Err(ace_testkit::HarnessError::Module(e)) => {
            assert!(e.to_string().contains("/nonexistent/magic.mgc"), "{e}")
        }
        other => panic!("{other:?}"),
    }
}
