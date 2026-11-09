//! PLAN.md 7.5: `url_extraction` and `ioc_extraction` against ace3's reference dumps, made from
//! `tools/ace3/dumps/fixtures/urls` and `fixtures/iocs` and the HTML samples. Every difference is
//! listed and explained in differences.md, next to this file.
//!
//! urlfinderlib returns a set, so ace3's order of URLs is its set's order, which the dumps fix with
//! `PYTHONHASHSEED=0`; ace4 sorts the set first. So where both hold the same URLs, ace3's lists
//! take ace4's order before the diff, and the test checks that ace4's order is the module's: the
//! URLs of the domains with the fewest URLs first, images last.

use std::collections::BTreeMap;
use std::path::Path;

use ace_mod_urls::{IocExtraction, UrlExtraction};
use ace_sdk::{Observable, Outcome};
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use ace_testkit::{Harness, HarnessError};
use serde_json::Value;

fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures")
}

/// The file a dump analyzed, with its directives and meta tags, and the mime type ace3's
/// file_type found, which is the one the core stores.
fn input<M: ace_sdk::Parser>(
    harness: &Harness<M>,
    dump: &Dump,
    fixture_dir: &str,
) -> Result<Observable, HarnessError> {
    let input = &dump.value["input"];
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_owned))
            .collect()
    };
    let alert_path = input["observable"]["file_path"]
        .as_str()
        .unwrap_or_default();
    let tags = strings(&input["meta_tags"]);
    let tags: Vec<&str> = tags.iter().map(String::as_str).collect();
    let label = input["label"].as_str().unwrap_or_default();
    let mut observable = if let Some(rest) = label.strip_prefix(&format!("fixtures/{fixture_dir}/"))
    {
        let name = rest.split(' ').next().unwrap_or_default();
        harness.file(alert_path, fixtures().join(fixture_dir).join(name), &tags)?
    } else {
        harness.sample(dump.short_name())?
    };
    for directive in strings(&input["directives"]) {
        observable = observable.with_directive(directive);
    }
    if let Some(file) = observable.file.as_mut() {
        file.mime_type = dump.mime_type().map(str::to_owned);
    }
    Ok(observable)
}

fn sorted(v: &Value) -> Vec<String> {
    let mut list: Vec<String> = v
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect();
    list.sort();
    list
}

/// Gives `theirs` the order of `ours` where the two lists hold the same strings.
fn same_members_take_our_order(theirs: &mut Value, ours: &Value) {
    if theirs.is_array() && ours.is_array() && sorted(theirs) == sorted(ours) {
        *theirs = ours.clone();
    }
}

/// The module's ranking: non-image URLs by their domain's count, ascending, then the images.
fn check_interest_order(details: &Value) {
    let groups: BTreeMap<&str, &Vec<Value>> = details["urls_grouped_by_domain"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, v)| (k.as_str(), v.as_array().expect("a list")))
        .collect();
    let size_of = |url: &str| {
        groups
            .values()
            .find(|list| list.iter().any(|u| u == url))
            .map_or(0, |list| list.len())
    };
    let image = |url: &str| {
        [".png", ".gif", ".jpeg", ".jpg", ".tiff", ".bmp"]
            .iter()
            .any(|ext| {
                ace_pycompat::parse::urlsplit(url, "", true).is_ok_and(|s| s.path.ends_with(ext))
            })
    };
    let urls: Vec<&str> = details["urls"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let first_image = urls.iter().position(|u| image(u)).unwrap_or(urls.len());
    assert!(urls[first_image..].iter().all(|u| image(u)), "{urls:?}");
    let sizes: Vec<usize> = urls[..first_image].iter().map(|u| size_of(u)).collect();
    assert!(sizes.windows(2).all(|w| w[0] <= w[1]), "{urls:?}");
}

fn compare<M: ace_sdk::Parser>(
    module: &str,
    class: &str,
    fixture_dir: &str,
    normalize: impl Fn(&mut Value, &Value),
) -> Vec<(String, Vec<ace_testkit::reference::Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        // url_extraction depends on file_type, whose result the dump holds
        let mut harness = Harness::<M>::new().expect("harness");
        if let Some(file_type) = dump.file_type() {
            harness = harness.dependency_result("file_type", file_type.clone());
        }
        let observable =
            input(&harness, &dump, fixture_dir).unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        // the fixtures ace-gui's analysis view test draws (PLAN.md 5.9)
        match (module, dump.short_name()) {
            ("url_extraction", "page.html") => {
                ace_testkit::check_view_fixture("urls_page_html", &outcome)
            }
            ("ioc_extraction", "report.txt") => {
                ace_testkit::check_view_fixture("iocs_report_txt", &outcome)
            }
            _ => {}
        }
        let mut theirs = dump.normal_form(class);
        let ours = normal_form(&outcome);
        if let Outcome::Done(_) = &outcome {
            normalize(&mut theirs, &ours);
        }
        compared.push((dump.short_name().to_owned(), diff(&theirs, &ours)));
    }
    compared
}

#[test]
fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = compare::<UrlExtraction>(
        "url_extraction",
        "URLExtractionAnalysis",
        "urls",
        |theirs, ours| {
            check_interest_order(&ours["details"]);
            same_members_take_our_order(&mut theirs["details"]["urls"], &ours["details"]["urls"]);
            if let (Some(t), Some(o)) = (
                theirs["details"]["urls_grouped_by_domain"].as_object_mut(),
                ours["details"]["urls_grouped_by_domain"].as_object(),
            ) {
                for (domain, list) in t.iter_mut() {
                    if let Some(our_list) = o.get(domain) {
                        same_members_take_our_order(list, our_list);
                    }
                }
            }
        },
    );
    let iocs = compare::<IocExtraction>(
        "ioc_extraction",
        "IOCExtractionAnalysis",
        "iocs",
        |theirs, ours| {
            if let (Some(t), Some(o)) = (
                theirs.pointer_mut("/details/iocs/url"),
                ours.pointer("/details/iocs/url"),
            ) {
                same_members_take_our_order(t, o);
            }
        },
    );
    assert!(compared.len() >= 20, "only {} url dumps", compared.len());
    assert!(iocs.len() >= 4, "only {} ioc dumps", iocs.len());
    compared.extend(iocs.into_iter().map(|(name, d)| (format!("ioc/{name}"), d)));
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
