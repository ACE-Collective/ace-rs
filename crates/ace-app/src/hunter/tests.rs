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
//!
//! PLAN.md 6.6: the `correlated*.yaml` cases correlate their rows with ace3's engine, their
//! queries going to the same fake through ace3's `SplunkQuerySource`. Their job forms match ace3's,
//! the correlation's included, and their submissions carry ace3's trace, original rows and
//! provenance, with the rows `differences.md` gives. The cases of ace3's `test_sources_loader.py`
//! and `test_splunk_source.py`, and `test_command_types.py`'s `TestLoadCommandTypesFromConfig`, are
//! at the end: ace3 builds its sources and command types from classes its configuration names, and
//! ace4's hunter builds its sources from its own configuration and takes its command types from the
//! binary (`App::command_type`).

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
        user_context: None,
        app_context: None,
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
        query_sources: default_query_sources(),
        correlation_cache_bytes: 1 << 20,
        scripts: BTreeMap::new(),
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
                .tick(&hunt, &state, "unknown", now, &CancellationToken::new())
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
        )
        .await;
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
            svs: None,
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

fn sources_config(query_sources: Json) -> HunterConfig {
    let mut config = config("https://127.0.0.1:1", Path::new("/nowhere"), "dev");
    config.query_sources = serde_json::from_value(query_sources).expect("a query source config");
    config
}

/// The hunter records what SVS reads of each hunt file it loads, whether or not the file loaded as a hunt
/// (PLAN.md 7.10 batch 5): a run's windows are computed by `ace serve`, which has no hunt files, from
/// these rows.
#[tokio::test]
async fn a_reload_records_what_svs_reads_of_each_hunt() {
    let work = tempfile::tempdir().expect("a directory");
    let hunts = copy_hunts(work.path());
    // a file that names a hunt and doesn't load as one still has its timing
    let broken = "11111111-aaaa-4aaa-8aaa-111111111111";
    std::fs::write(
        hunts.join("broken.yaml"),
        format!(
            "rule:\n  uuid: {broken}\n  name: broken\n  enabled: true\n  type: splunk\n  \
             frequency: '00:10:00'\n  time_range: '01:00:00'\n  suppression: '02:00:00'\n  \
             tags: [b, a, b]\n"
        ),
    )
    .expect("writes a hunt");
    let config = config("https://127.0.0.1:8089", &hunts, "PRODUCTION");
    let hunter = Hunter::new(config.clone(), &secrets())
        .expect("a hunter")
        .with_home(work.path().to_owned());
    let app = App::new().hunt_type(ace_hunt::types::Splunk::default());
    let recorder = Recorder::new().await;

    let loaded = super::reload(&app, &hunter, &recorder.service, &recorder.actor, &config).await;

    let rows = recorder
        .service
        .hunts(&recorder.actor)
        .await
        .expect("the hunts");
    assert!(!loaded.is_empty() && rows.len() > loaded.len(), "{rows:?}");
    for row in &rows {
        let svs = row.hunt.svs.as_ref().unwrap_or_else(|| panic!("{row:?}"));
        match &row.hunt.error {
            // a hunt that loaded: SVS reads the same uuid and switch the hunter runs it by
            None => assert_eq!(
                (Some(&svs.uuid), Some(svs.enabled)),
                (row.hunt.uuid.as_ref(), row.hunt.enabled),
                "{row:?}"
            ),
            Some(_) => assert_eq!(row.hunt.path, "broken.yaml", "{row:?}"),
        }
        assert_eq!(svs.content_hash.len(), 64);
    }
    let failed = rows
        .iter()
        .find(|row| row.hunt.path == "broken.yaml")
        .expect("the file that didn't load");
    assert!(failed.hunt.error.is_some() && failed.hunt.name.is_none());
    let svs = failed.hunt.svs.as_ref().expect("its svs info");
    assert_eq!(
        serde_json::to_value(svs).expect("JSON"),
        json!({
            "uuid": broken, "name": "broken", "enabled": true, "latency_seconds": 4200,
            "suppression_seconds": 7200, "per_group": false, "content_hash": svs.content_hash,
            "tags": ["a", "b"],
        })
    );
    // and that is what a registration's windows read
    let pool = recorder._db.db().pool();
    let mut conn = pool.acquire().await.expect("a connection");
    let recorded = ace_core::svs::windows::recorded_hunts(&mut conn)
        .await
        .expect("reads the recorded hunts");
    assert_eq!(recorded.len(), rows.len());
    assert_eq!(
        ace_core::svs::windows::hunt_latencies(&recorded)[broken],
        chrono::TimeDelta::minutes(70)
    );
    // loading the same files again records nothing new
    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM service.audit")
        .fetch_one(pool)
        .await
        .expect("counts");
    super::reload(&app, &hunter, &recorder.service, &recorder.actor, &config).await;
    let again: i64 = sqlx::query_scalar("SELECT count(*) FROM service.audit")
        .fetch_one(pool)
        .await
        .expect("counts");
    assert_eq!(again, audited);
}

/// test_sources_loader.py test_registers_configured_source: a source as configured, on the
/// instance it names (ace3's `kwargs`).
#[tokio::test(flavor = "multi_thread")]
async fn test_registers_configured_source() {
    let hunter = Hunter::new(
        sources_config(json!({"rec": {"type": "splunk", "instance": "eastern"}})),
        &secrets(),
    )
    .expect("a hunter");
    let sources = hunter.query_sources(&CancellationToken::new());
    assert_eq!(sources.names(), ["rec"]);
    // eastern's timezone is the one its display uses
    let spec = sources
        .get("rec")
        .expect("registered")
        .format_timespec_for_display(
            Time::from(
                DateTime::parse_from_rfc3339("2026-05-18T12:26:32Z")
                    .expect("a time")
                    .with_timezone(&Utc),
            ),
            Time::from(
                DateTime::parse_from_rfc3339("2026-05-18T12:31:32Z")
                    .expect("a time")
                    .with_timezone(&Utc),
            ),
        )
        .expect("formats");
    // test_splunk_source.py test_format_timespec_uses_configured_timezone: UTC 12:26-12:31 is
    // EDT 08:26-08:31 on 2026-05-18
    assert_eq!(
        spec.as_deref(),
        Some("earliest=05/18/2026:08:26:32 latest=05/18/2026:08:31:32")
    );
}

/// test_loaded_flag_prevents_double_registration and test_force_reloads: ace3 keeps its sources in
/// a module global loaded once; ace4 builds them for each correlation from the configuration, so a
/// run's sources are always the configuration's, and a stop ends only that run's.
#[tokio::test(flavor = "multi_thread")]
async fn test_loaded_flag_prevents_double_registration() {
    let hunter = Hunter::new(
        sources_config(json!({"rec": {"type": "splunk", "instance": "default"}})),
        &secrets(),
    )
    .expect("a hunter");
    let first = hunter.query_sources(&CancellationToken::new());
    let second = hunter.query_sources(&CancellationToken::new());
    assert_eq!(first.names(), second.names());
}

/// test_failing_source_does_not_abort_others: a source on an instance the hunter hasn't fails to
/// load, as ace3's source whose class raises, and the others load.
#[tokio::test(flavor = "multi_thread")]
async fn test_failing_source_does_not_abort_others() {
    let hunter = Hunter::new(
        sources_config(json!({
            "boom": {"type": "splunk", "instance": "no_such_splunk"},
            "rec": {"type": "splunk", "instance": "default"},
        })),
        &secrets(),
    )
    .expect("a hunter");
    let sources = hunter.query_sources(&CancellationToken::new());
    assert!(sources.get("rec").is_ok());
    assert!(matches!(sources.get("boom"), Err(e) if e.contains("not registered")));
}

/// test_no_op_when_hunter_config_absent.
#[tokio::test(flavor = "multi_thread")]
async fn test_no_op_when_hunter_config_absent() {
    let hunter = Hunter::new(sources_config(json!({})), &secrets()).expect("a hunter");
    assert!(hunter.query_sources(&CancellationToken::new()).is_empty());
}

/// test_splunk_source.py test_default_config_name: with no `query_sources`, `splunk` is the
/// `default` instance, as ace3's default configuration registers it.
#[test]
fn test_default_config_name() {
    let config: HunterConfig = serde_json::from_value(json!({
        "signatures": "/nowhere", "rule_dirs": {}, "instance_type": "dev",
    }))
    .expect("a config");
    assert_eq!(
        config.query_sources,
        BTreeMap::from([(
            "splunk".to_owned(),
            QuerySourceConfig::Splunk {
                instance: "default".to_owned()
            }
        )])
    );
}

/// test_default_time_field_and_format.
#[tokio::test(flavor = "multi_thread")]
async fn test_default_time_field_and_format() {
    let hunter = Hunter::new(
        sources_config(json!({"splunk": {"type": "splunk", "instance": "default"}})),
        &secrets(),
    )
    .expect("a hunter");
    let sources = hunter.query_sources(&CancellationToken::new());
    let splunk = sources.get("splunk").expect("registered");
    assert_eq!(splunk.default_time_field(), Some("_time"));
    assert_eq!(splunk.default_time_format(), Some("iso8601"));
}

/// test_execute_query_passes_correct_params: the job has the query and its window, as ace3's
/// SplunkClient.query makes it; test_execute_query_returns_results and
/// test_execute_query_accepts_and_ignores_source_options are the correlated cases above, whose
/// queries' rows are ace3's and whose forms match ace3's.
#[test]
fn test_execute_query_passes_correct_params() {
    let start = Time::from(
        DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .expect("a time")
            .with_timezone(&Utc),
    );
    let end = Time::from(
        DateTime::parse_from_rfc3339("2024-01-02T00:00:00Z")
            .expect("a time")
            .with_timezone(&Utc),
    );
    assert_eq!(
        splunk::correlation_form("search index=main", start, end),
        [
            (
                "search",
                "search earliest=01/01/2024:00:00:00 latest=01/02/2024:00:00:00  index=main"
            ),
            ("max_count", "1000"),
            ("exec_mode", "normal"),
            ("earliest_time", "2024-01-01T00:00:00+00:00"),
            ("latest_time", "2024-01-02T00:00:00+00:00"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
    );
    // a generating command is sent as it is
    assert_eq!(
        splunk::correlation_form("| inputlookup x", start, end)[0].1,
        "| inputlookup x"
    );
}

/// test_format_timespec_unknown_config_raises: ace3 raises when it formats for an instance it
/// hasn't; ace4 never builds a source for one (test_failing_source_does_not_abort_others).
#[tokio::test(flavor = "multi_thread")]
async fn test_format_timespec_unknown_config_raises() {
    let hunter = Hunter::new(
        sources_config(json!({"splunk": {"type": "splunk", "instance": "no_such_splunk"}})),
        &secrets(),
    )
    .expect("a hunter");
    assert!(
        hunter
            .query_sources(&CancellationToken::new())
            .get("splunk")
            .is_err()
    );
}

struct Echo(String);

impl ace_hunt::correlate::command::CommandType for Echo {
    fn execute(
        &self,
        _: &ace_hunt::correlate::command::CommandContext<'_>,
        _: &Json,
    ) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

/// test_command_types.py TestLoadCommandTypesFromConfig: ace3 imports each configured class with
/// its `kwargs`; ace4's binary adds each with `App::command_type`, the integration's own settings in
/// what it builds.
#[test]
fn test_registers_configured_type_with_kwargs() {
    let app = App::new().command_type("echo", || Ok(Arc::new(Echo(">> ".to_owned()))));
    let types = app.command_types();
    assert_eq!(types.names(), ["echo"]);
}

/// test_loaded_flag_prevents_reload: the registry is built once a process, each call a fresh one.
#[test]
fn test_loaded_flag_prevents_reload() {
    let app = App::new().command_type("echo", || Ok(Arc::new(Echo(String::new()))));
    let (first, second) = (app.command_types(), app.command_types());
    assert!(!Arc::ptr_eq(
        first.get("echo").expect("registered"),
        second.get("echo").expect("registered")
    ));
}

#[test]
fn test_failing_type_does_not_abort_others() {
    let app = App::new()
        .command_type("boom", || Err("RuntimeError: constructor boom".to_owned()))
        .command_type("echo", || Ok(Arc::new(Echo(String::new()))));
    let types = app.command_types();
    assert!(types.get("echo").is_ok());
    assert!(types.load_errors()["boom"].contains("constructor boom"));
    // the failure, not a bare unknown type, is what a hunt using it is told
    assert!(
        matches!(types.get("boom"), Err(e) if e.contains("failed to load: RuntimeError: constructor boom"))
    );
}

#[test]
fn test_no_op_when_hunter_config_absent_for_types() {
    assert!(App::new().command_types().names().is_empty());
}

/// test_config_entry_rejects_unknown_keys: ace3's configuration entry is a model; ace4's is a call,
/// whose name is checked as ace3 checks a registered one.
#[test]
fn test_config_entry_rejects_unknown_keys() {
    let app = App::new().command_type("Echo", || Ok(Arc::new(Echo(String::new()))));
    let types = app.command_types();
    assert!(types.names().is_empty());
    assert!(types.load_errors()["Echo"].contains("invalid correlation command type name"));
}

/// test_default_config_declares_no_command_types: the open-source binary adds none.
#[test]
fn test_default_config_declares_no_command_types() {
    assert!(App::new().command_types().names().is_empty());
}

/// `rule_dirs` naming a hunt type the binary lacks is a warning when the hunter starts, so a type a
/// site's binary would add isn't silently never loaded.
#[test]
fn rule_dirs_naming_a_type_the_binary_lacks_is_found() {
    let mut config = config("http://127.0.0.1:1", Path::new("/signatures"), "DEV");
    let app = crate::App::new().hunt_type(ace_hunt::types::Splunk::default());
    assert!(unknown_types(&app, &config).is_empty());
    config
        .rule_dirs
        .insert("rapid7".to_owned(), vec![PathBuf::from("hunts/rapid7")]);
    config
        .rule_dirs
        .insert("endpoint".to_owned(), vec![PathBuf::from("hunts/endpoint")]);
    assert_eq!(unknown_types(&app, &config), ["endpoint", "rapid7"]);
}
