//! The Done check of PLAN.md 6.4 for Splunk: the hunts in `tools/ace3/hunts/query/hunts`, run at the
//! ticks in `runs.yaml` against ace3's recorded exchanges with `fake_splunk.py`, make the same
//! submissions ace3's hunter made (`tools/ace3/hunts/reference/query.json`, from `make-query-hunts`),
//! send the same job forms, skip the same ticks and leave the same state. A difference in a submission
//! is accepted only where `tools/ace3/hunts/differences.md` lists it, in its set `query`, whose Hunts
//! column is `<hunt file> tick <n>`.
//!
//! PLAN.md 6.5: each tick that ran is recorded as `ace hunter` records it (`run_of`, then
//! `Service::record_hunt_run`) in a test database, and its suppression rows are the decisions ace3
//! made that tick: each group `record_suppressed` was handed, and each staged submission ace3's
//! `DuplicateSubmissionFilter` dropped. Each row points at the root of the earlier hit, and every other
//! submission is a root with no row.

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
    let recorder = Recorder::new().await;
    let mut decisions = 0;
    let mut reasons = std::collections::BTreeSet::new();
    for (name, ticks) in reference["cases"].as_object().expect("cases") {
        let hunt = ace_hunt::load_hunt(
            &hunts.join(name),
            &ace_hunt::types::Splunk::default(),
            &LoadOptions::default(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        recorder.loaded(&hunt, name).await;
        let mut state = State::default();
        // the root each dedup key and each group's alert points to, as ace3's decisions say
        let mut made: BTreeMap<String, (uuid::Uuid, DateTime<Utc>)> = BTreeMap::new();
        let mut groups: BTreeMap<String, uuid::Uuid> = BTreeMap::new();
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

                let run = run_of(&hunt, to_service(&state), &ran, now);
                let recorded = recorder
                    .service
                    .record_hunt_run(&recorder.actor, &recorder.bucket, &run)
                    .await
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                let duplicates: Vec<usize> = tick["duplicates"]
                    .as_array()
                    .expect("duplicates")
                    .iter()
                    .map(|d| usize::try_from(d.as_u64().expect("an index")).expect("an index"))
                    .collect();
                let mut expected = Vec::new();
                for group in tick["suppressed"].as_array().expect("suppressed") {
                    let key = query::group_key(&group["group_value"]);
                    expected.push(json!({
                        "reason": "group",
                        "key": key,
                        "group_value": group["group_value"],
                        "description": group["description"],
                        "event_time": group["event_time"],
                        "window_start": group["window_start"],
                        "window_end": group["window_end"],
                        "cause_root": groups.get(&key).map(ToString::to_string),
                    }));
                }
                let tracks_groups =
                    hunt.config.group_by.is_some() && schedule::suppression(&hunt.config).is_some();
                let mut roots = recorded.roots.iter();
                for (index, submission) in ace3.iter().enumerate() {
                    let key = submission["key"].as_str().map(str::to_owned);
                    let root = if duplicates.contains(&index) {
                        let key = key.clone().expect("a duplicate has a key");
                        let (cause, since) = made[&key];
                        expected.push(json!({
                            "reason": "duplicate",
                            "key": key,
                            "group_value": submission["group_value"],
                            "description": submission["description"],
                            "event_time": submission["event_time"],
                            "window_start": isoformat(&since),
                            "window_end": isoformat(&(since + ace_service::DEDUP_KEY_LIFETIME)),
                            "cause_root": cause.to_string(),
                        }));
                        cause
                    } else {
                        let root = *roots
                            .next()
                            .unwrap_or_else(|| panic!("{label}: too few roots"));
                        if let Some(key) = key {
                            made.insert(key, (root, now));
                        }
                        root
                    };
                    if tracks_groups && !submission["group_value"].is_null() {
                        groups.insert(query::group_key(&submission["group_value"]), root);
                    }
                }
                assert!(roots.next().is_none(), "{label}: a root ace3 didn't make");
                let rows = recorder.rows(&hunt, &recorded.suppressions).await;
                assert_eq!(rows, expected, "{label}: the suppression rows");
                decisions += rows.len();
                reasons.extend(rows.iter().map(|r| r["reason"].to_string()));
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
    assert!(
        decisions >= 4 && reasons.len() == 2,
        "only {decisions} decisions, {reasons:?}"
    );
}

/// A test database to record the runs in, as `ace hunter` does.
struct Recorder {
    _db: ace_core::testing::TestDb,
    _cache: tempfile::TempDir,
    service: ace_service::Service,
    bucket: ace_core::bucket::Bucket,
    actor: ace_service::Actor,
}

impl Recorder {
    async fn new() -> Recorder {
        use ace_core::bucket::{Bucket, BucketSettings};
        use ace_store::{BucketConfig, NodeCache, Store};

        let db = ace_core::testing::TestDb::new().await;
        let cache = tempfile::tempdir().expect("a cache directory");
        let store = Store::new(
            &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
            NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
        );
        let orchestrator = ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new(vec![]),
            ace_core::modes::Modes::ace3(),
        );
        Recorder {
            service: ace_service::Service::new(db.db().clone(), orchestrator),
            bucket: Bucket::new(db.db().clone(), store, BucketSettings::default()),
            actor: ace_service::Actor::Internal {
                id: ace_service::Component::new("hunter").expect("valid"),
            },
            _db: db,
            _cache: cache,
        }
    }

    /// Records a hunt as loaded, so its suppressions can be listed by its uuid.
    async fn loaded(&self, hunt: &Hunt, path: &str) {
        let row = ace_service::LoadedHuntRow {
            kind: "splunk".to_owned(),
            path: path.to_owned(),
            name: Some(hunt.config.name.clone()),
            uuid: Some(hunt.config.uuid.clone()),
            enabled: Some(hunt.config.enabled),
            frequency: Some(hunt.config.frequency.clone()),
            error: None,
        };
        let mut rows: Vec<ace_service::LoadedHuntRow> = self
            .service
            .hunts(&self.actor)
            .await
            .expect("lists")
            .into_iter()
            .map(|h| h.hunt)
            .collect();
        rows.push(row);
        self.service
            .sync_hunts(&self.actor, "splunk", &rows)
            .await
            .expect("records");
    }

    /// The rows a run wrote, as listed through the `hunt` router's service function, oldest first.
    async fn rows(&self, hunt: &Hunt, ids: &[i64]) -> Vec<Json> {
        let page = self
            .service
            .hunt_suppressions(&self.actor, &hunt.config.uuid, Some(500), None)
            .await
            .expect("lists");
        let mut rows: Vec<&ace_service::Suppression> = page
            .suppressions
            .iter()
            .filter(|s| ids.contains(&s.id))
            .collect();
        rows.sort_by_key(|s| s.id);
        rows.into_iter()
            .map(|s| {
                json!({
                    "reason": s.reason,
                    "key": s.key,
                    "group_value": s.group_value,
                    "description": s.description,
                    "event_time": isoformat(&s.event_time),
                    "window_start": isoformat(&s.window_start),
                    "window_end": isoformat(&s.window_end),
                    "cause_root": s.cause_root.map(|r| r.to_string()),
                })
            })
            .collect()
    }
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
