//! The Done check of PLAN.md 6.4 for Splunk: the hunts in `tools/ace3/hunts/query/hunts`, run at the
//! ticks in `runs.yaml` against ace3's recorded exchanges with `fake_splunk.py`, make the same
//! submissions ace3's hunter made (`tools/ace3/hunts/reference/query.json`, from `make-query-hunts`),
//! send the same job forms, skip the same ticks and leave the same state. A difference in a submission
//! is accepted only where `tools/ace3/hunts/differences.md` lists it, in its set `query`, whose Hunts
//! column is `<hunt file> tick <n>`.

use std::path::{Path, PathBuf};

use ace_hunt::normal::{Difference, classify, parse_rows};
use ace_hunt::query::isoformat;
use ace_hunt::query::schedule::State;
use ace_sdk::{Secret, Secrets};
use ace_testkit::replay::HttpReplay;
use chrono::{DateTime, Utc};
use serde_json::{Value as Json, json};

use super::*;

fn tools() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/hunts")
}

/// The cases' hunts, copied with `$QUERIES` pointing at their query files, as ace3's run did.
fn copy_hunts(into: &Path) -> PathBuf {
    let from = tools().join("query/hunts");
    let to = into.join("hunts");
    let queries = to.join("queries");
    for entry in walk(&from) {
        let relative = entry.strip_prefix(&from).expect("under the hunts");
        let target = to.join(relative);
        std::fs::create_dir_all(target.parent().expect("a parent")).expect("a directory");
        let text = std::fs::read_to_string(&entry).expect("a case file");
        let text = if entry.extension().is_some_and(|e| e == "yaml") {
            text.replace("$QUERIES", &queries.to_string_lossy())
        } else {
            text
        };
        std::fs::write(&target, text).expect("written");
    }
    to
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("a directory").flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// One tick's exchanges as an `HttpReplay` recording.
fn recording(dir: &Path, exchanges: &[Json]) {
    std::fs::create_dir_all(dir).expect("a directory");
    let mut recorded = Vec::new();
    for (i, exchange) in exchanges.iter().enumerate() {
        let body_file = format!("{i:03}.body");
        std::fs::write(
            dir.join(&body_file),
            exchange["body"].as_str().unwrap_or_default(),
        )
        .expect("written");
        recorded.push(json!({
            "method": exchange["method"],
            "url": exchange["url"],
            "status": exchange["status"],
            "response_headers": {"Content-Type": exchange["content_type"]},
            "body_file": body_file,
        }));
    }
    std::fs::write(
        dir.join("http.json"),
        json!({"exchanges": recorded}).to_string(),
    )
    .expect("written");
}

fn config(base_url: &str, signatures: &Path, instance_type: &str) -> HunterConfig {
    let instance = |timezone: &str| SplunkInstance {
        host: "127.0.0.1".to_owned(),
        port: 8089,
        base_url: Some(base_url.to_owned()),
        username: Some("ace4".to_owned()),
        timezone: timezone.to_owned(),
        ca_certificates: None,
        request_timeout_seconds: 10,
        dispatch_timeout_seconds: 900,
    };
    HunterConfig {
        signatures: signatures.to_owned(),
        rule_dirs: BTreeMap::from([("splunk".to_owned(), vec![PathBuf::from(".")])]),
        splunk: BTreeMap::from([
            ("default".to_owned(), instance("GMT")),
            ("eastern".to_owned(), instance("America/New_York")),
        ]),
        instance_type: instance_type.to_owned(),
        tick_seconds: 1,
        reload_seconds: 60,
        poll_seconds: 0.0,
        concurrency: 1,
    }
}

fn secrets() -> Secrets {
    let mut secrets = Secrets::new();
    for name in ["default", "eastern"] {
        let [password, _] = secret_names(name);
        secrets = secrets.with(password, Secret::new("ace4-fake-password".to_owned()));
    }
    secrets
}

fn time(value: Option<DateTime<Utc>>) -> Json {
    value.map_or(Json::Null, |t| json!(isoformat(&t)))
}

fn state_json(state: &State) -> Json {
    json!({
        "last_executed_time": time(state.last_executed_time),
        "last_end_time": time(state.last_end_time),
        "last_alert_time": time(state.last_alert_time),
        "last_alert_times": state.last_alert_times.iter().map(|(k, v)| (k.clone(), json!(isoformat(v)))).collect::<serde_json::Map<_, _>>(),
    })
}

fn ace4_submission(submission: &ace_hunt::query::Submission) -> Json {
    let mut value = serde_json::to_value(submission).expect("JSON");
    value.as_object_mut().expect("an object").remove("files");
    value
}

/// Where two values differ, by the JSON pointer of each difference.
fn diff(ace3: &Json, ace4: &Json, hunt: &str, pointer: &str, out: &mut Vec<Difference>) {
    match (ace3, ace4) {
        (Json::Object(a), Json::Object(b)) => {
            for key in a.keys().chain(b.keys().filter(|k| !a.contains_key(*k))) {
                let next = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => diff(x, y, hunt, &next, out),
                    (x, y) => out.push(Difference {
                        hunt: hunt.to_owned(),
                        pointer: next,
                        ace3: x.cloned(),
                        ace4: y.cloned(),
                    }),
                }
            }
        }
        (Json::Array(a), Json::Array(b)) if a.len() == b.len() => {
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                diff(x, y, hunt, &format!("{pointer}/{i}"), out);
            }
        }
        (a, b) if a != b => out.push(Difference {
            hunt: hunt.to_owned(),
            pointer: pointer.to_owned(),
            ace3: Some(a.clone()),
            ace4: Some(b.clone()),
        }),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cases_submit_as_ace3_s_hunter_does() {
    let reference: Json = serde_json::from_str(
        &std::fs::read_to_string(tools().join("reference/query.json"))
            .expect("make-query-hunts' output"),
    )
    .expect("JSON");
    let instance_type = reference["instance_type"]
        .as_str()
        .expect("an instance type");
    let work = tempfile::tempdir().expect("a directory");
    let hunts = copy_hunts(work.path());
    let mut differences = Vec::new();
    let mut compared = 0;
    for (name, ticks) in reference["cases"].as_object().expect("cases") {
        let hunt = ace_hunt::load_hunt(
            &hunts.join(name),
            &ace_hunt::types::Splunk::default(),
            &LoadOptions::default(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut state = State::default();
        for (i, tick) in ticks.as_array().expect("ticks").iter().enumerate() {
            let label = format!("{name} tick {i}");
            let now = DateTime::parse_from_rfc3339(tick["now"].as_str().expect("a time"))
                .expect("a time")
                .with_timezone(&Utc);
            let exchanges = tick["exchanges"].as_array().cloned().unwrap_or_default();
            let dir = work.path().join(format!("http/{name}/{i}"));
            recording(&dir, &exchanges);
            let replay = HttpReplay::start(&dir, &[]).await.expect("the replay");
            let hunter = Hunter::new(
                config(
                    &replay.local_url("https://127.0.0.1:8089"),
                    &hunts,
                    instance_type,
                ),
                &secrets(),
            )
            .expect("a hunter")
            .with_home(work.path().to_owned());
            let ran = hunter
                .tick(&hunt, &state, "unknown", now, std::future::pending())
                .await;
            assert_eq!(ran.error, None, "{label}");
            assert_eq!(
                ran.skipped.as_deref(),
                tick["skipped"].as_str(),
                "{label}: skipped"
            );
            if ran.skipped.is_none() {
                // the job's form, which holds the search and its window
                let sent: Vec<String> = replay
                    .requests()
                    .into_iter()
                    .filter(|r| r.method == "POST" && r.url.ends_with("/jobs/"))
                    .map(|r| String::from_utf8_lossy(&r.body).into_owned())
                    .collect();
                let recorded: Vec<String> = exchanges
                    .iter()
                    .filter(|e| {
                        e["method"] == "POST"
                            && e["url"].as_str().is_some_and(|u| u.ends_with("/jobs/"))
                    })
                    .map(|e| e["request_body"].as_str().unwrap_or_default().to_owned())
                    .collect();
                assert_eq!(sent, recorded, "{label}: the job's form");
                assert!(
                    replay.unmatched().is_empty(),
                    "{label}: {:?}",
                    replay.unmatched()
                );
                let ace3: Vec<Json> = tick["submissions"].as_array().expect("submissions").clone();
                let ace4: Vec<Json> = ran
                    .processed
                    .submissions
                    .iter()
                    .map(ace4_submission)
                    .collect();
                diff(
                    &json!(ace3),
                    &json!(ace4),
                    &label,
                    "/submissions",
                    &mut differences,
                );
                compared += ace3.len();
            }
            assert_eq!(
                state_json(&ran.state),
                tick["state"],
                "{label}: the state after"
            );
            state = ran.state;
        }
    }
    let rows = parse_rows(
        &std::fs::read_to_string(tools().join("differences.md")).expect("differences.md"),
        "query",
    );
    let report = classify(differences, &rows);
    let unexplained: Vec<String> = report
        .unexplained
        .iter()
        .map(|d| {
            format!(
                "{} {}: ace3 {:?} ace4 {:?}",
                d.hunt, d.pointer, d.ace3, d.ace4
            )
        })
        .collect();
    assert!(unexplained.is_empty(), "{}", unexplained.join("\n"));
    assert!(
        report.unused.is_empty(),
        "rows that explain nothing: {:?}",
        report.unused
    );
    assert!(compared >= 15, "compared only {compared} submissions");
}

/// A submission reaches the core with its detection on its signature_id observable, its event time's
/// source, and the rest of what ace3 records as its origin.
#[test]
fn a_hunt_submission_becomes_the_core_s() {
    let submission: ace_hunt::query::Submission = {
        let reference: Json = serde_json::from_str(
            &std::fs::read_to_string(tools().join("reference/query.json")).expect("the reference"),
        )
        .expect("JSON");
        let _ = reference;
        ace_hunt::query::Submission {
            key: None,
            group_value: None,
            suppression_key: None,
            description: "d".to_owned(),
            instructions: "i".to_owned(),
            analysis_mode: "correlation".to_owned(),
            alert_type: "a".to_owned(),
            queue: "default".to_owned(),
            tool: "hunter-splunk".to_owned(),
            tool_instance: "h".to_owned(),
            event_time: Utc::now(),
            event_time_source: EventTimeSource::QueryTime,
            details: serde_json::Map::new(),
            extensions: serde_json::Map::new(),
            tags: vec![],
            pivot_links: vec![],
            summary_details: vec![],
            detections: vec![ace_hunt::query::Detection {
                description: "hunt x (splunk) matched".to_owned(),
                signature_uuid: "u".to_owned(),
                signature_version: "unknown".to_owned(),
                signature_family: "hunt".to_owned(),
            }],
            observables: vec![
                ace_hunt::query::observable::Observable::create("signature_id", "u", false, |v| {
                    Some(v.to_owned())
                })
                .expect("made"),
                ace_hunt::query::observable::Observable::create("no_such_type", "x", false, |v| {
                    Some(v.to_owned())
                })
                .expect("made"),
            ],
            files: vec![],
            rows: vec![],
        }
    };
    let (core, origin) = to_core(&submission);
    assert_eq!(core.analysis_mode.as_deref(), Some("correlation"));
    assert!(origin.event_time_from_query);
    assert_eq!(
        origin.observables.len(),
        1,
        "the unknown type is in the origin only"
    );
    assert_eq!(origin.observables[0].detections.len(), 1);
    assert_eq!(
        origin.details.as_ref().expect("details")["alert_type"],
        json!("a")
    );
}
