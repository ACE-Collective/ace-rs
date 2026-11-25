//! PLAN.md 7.7: the two scanner modules against ace3's reference dumps
//! (`tools/ace3/dumps/make-dumps javascript_deobfuscation phishkit_analyzer`). ace3's modules were
//! answered, in place of their Celery managers, with the output directories in
//! `tools/ace3/dumps/fixtures/scanners/`, which `tools/ace3/dumps/scanner-fixtures` made by running the
//! scanner images as the managers run them. Here each module's first run asks for its scan, which is
//! checked against what ace3's asked its manager for, and its second run reads the same directory, as
//! the scanner pool would bring it back: Docker's tar of the output directory and the two log
//! streams, with the exit code beside them. Every difference is listed in differences.md, next to
//! this file.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ace_mod_scanners::{JavaScriptDeobfuscationAnalyzer, PhishkitAnalyzer};
use ace_results::ObservableKind;
use ace_results::types::file_type::TypeFacts;
use ace_sdk::scanners::{Scan, ScanState};
use ace_sdk::tree::{TreeObservable, TreePath, TreeView};
use ace_sdk::{Delay, Outcome};
use ace_testkit::Harness;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use serde_json::{Value, json};

/// The job id in the fixtures' paths, and in ace3's file paths.
const FIXED_JOB: &str = "00000000-0000-4000-8000-000000000000";

fn listed(name: &str) -> ListedDifferences {
    ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(name),
    )
    .expect("the differences read")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/scanners")
}

/// The files the managers write beside the scanner's: what the scanner pool brings back instead as
/// the logs and the exit code, or what the module makes itself.
const MANAGER_FILES: &[&str] = &[
    "std.out",
    "std.err",
    "exit.code",
    "report.json",
    "proxy.json",
];

/// A scan of the output directory `dir` as the scanner pool brings it back, with the exit code the
/// manager wrote.
fn scan_of(dir: &Path, under: &str, state: ScanState, work: &Path) -> Scan {
    let read = |name: &str| std::fs::read(dir.join(name)).unwrap_or_default();
    let mut inner = tar::Builder::new(Vec::new());
    let mut files: Vec<PathBuf> = walk(dir);
    files.sort();
    for path in files {
        let relative = path.strip_prefix(dir).expect("under it");
        if relative.components().count() == 1
            && MANAGER_FILES.contains(&relative.to_str().unwrap_or_default())
        {
            continue;
        }
        let bytes = std::fs::read(&path).expect("reads");
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        inner
            .append_data(
                &mut header,
                Path::new("output").join(under).join(relative),
                &bytes[..],
            )
            .expect("appends");
    }
    let framed = |stream: u8, bytes: Vec<u8>| {
        let mut out = vec![stream, 0, 0, 0];
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
        out
    };
    let mut outer = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("output.tar", inner.into_inner().expect("a tar")),
        ("stdout", framed(1, read("std.out"))),
        ("stderr", framed(2, read("std.err"))),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        outer
            .append_data(&mut header, name, &bytes[..])
            .expect("appends");
    }
    let path = work.join("scan.tar");
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(&outer.into_inner().expect("a tar")))
        .expect("writes");
    let exit_code = String::from_utf8_lossy(&read("exit.code"))
        .trim()
        .parse()
        .ok();
    Scan {
        id: 1,
        scanner: String::new(),
        state,
        exit_code,
        error: None,
        output: Some(path),
        proxied: None,
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// The fixture a phishkit dump's scan was answered with (make-dumps' `phishkit_runs`).
fn phishkit_case(dump: &Dump) -> &'static str {
    match dump.short_name() {
        "url_scan" | "url_no_crawl" => "url_scan",
        "url_partial" => "url_partial",
        "url_script" => "url_script",
        "url_failed" => "url_failed",
        _ => "file_render",
    }
}

// ---- javascript_deobfuscation ----

/// The fixture each JS dump's scan answered with, and the state the scan ended in.
fn js_case(dump: &Dump) -> (Option<&'static str>, ScanState) {
    match dump.short_name().rsplit('/').next().unwrap_or_default() {
        "dropper.js" | "dropper.js.tagged" => (Some("dropper"), ScanState::Completed),
        "broken.js" => (Some("broken"), ScanState::Completed),
        "blob_redirect.js" => (Some("blob_redirect"), ScanState::Completed),
        "runtime_error.js" => (Some("runtime_error"), ScanState::Completed),
        "scripts.html.inline_0" => (Some("scripts_inline"), ScanState::Completed),
        // Celery's `result.get` ran out of time: here the task's delay ran out with the scan pending
        "dropper.js.celery_timeout" => (None, ScanState::Pending),
        _ => (None, ScanState::Completed),
    }
}

/// The script a JS dump analyzed, as the harness makes it.
fn js_input(
    harness: &Harness<JavaScriptDeobfuscationAnalyzer>,
    dump: &Dump,
) -> ace_sdk::Observable {
    let observable = &dump.value["input"]["observable"];
    let path = observable["file_path"].as_str().expect("a path");
    let meta: Vec<&str> = dump.value["input"]["meta_tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        // what html_js_extraction gives a script it writes; file_type's own type isn't the module's
        .filter(|m| !m.starts_with("type=document"))
        .collect();
    match dump.short_name().rsplit('/').next().unwrap_or_default() {
        "scripts.html.inline_0" => harness
            .file_bytes(
                path,
                b"var redirect = document.getElementById('d').getAttribute('data-u'); window.location = redirect;",
                &meta,
            )
            .expect("the script"),
        _ => {
            // the sample make-dumps' `js_runs` named, without the run's suffix
            let name = dump.name.trim_start_matches("javascript_deobfuscation/");
            let sample = ["ace-rs/js/dropper.js", "ace-rs/js/broken.js", "ace-rs/js/blob_redirect.js",
                "ace-rs/js/runtime_error.js", "ace-rs/js/report.JS", "ace-rs/js/loader.mjs"]
                .into_iter()
                .find(|s| name.starts_with(s))
                .unwrap_or_else(|| panic!("no sample for {name}"));
            harness
                .file(path, ace_testkit::samples_dir().join(sample), &meta)
                .expect("the sample")
        }
    }
}

/// The root the scripts.html dump kept, with html_js_extraction's result holding the snapshot ace3
/// wrote beside the script, as ace-rs's keeps it in its details (7.5 batch 4).
fn js_tree(dump: &Dump, path: &str) -> Option<TreeView> {
    dump.value.get("tree_view")?;
    let this = dump.value["tree_view"]["observables"]
        .as_array()?
        .iter()
        .position(|o| {
            o["paths"]
                .as_array()
                .is_some_and(|ps| ps.iter().any(|p| p["path"] == path))
        })?;
    let mut tree = dump.tree_view(this, &["JavaScriptDeobfuscationAnalysis"]);
    // the root the dump kept is the one after the run: the files the module wrote weren't there before
    for observable in &mut tree.observables {
        observable.paths.retain(|p| {
            !p.path
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .starts_with("deobfuscated-")
        });
    }
    let sidecars = dump.value["sidecars"].as_object()?;
    for result in &mut tree.results {
        if result.module != "html_js_extraction" {
            continue;
        }
        let snapshots: Vec<Value> = sidecars
            .iter()
            .map(|(name, text)| {
                json!({
                    "files": [name.trim_end_matches(".dom.json")],
                    "snapshot": serde_json::from_str::<Value>(text.as_str().unwrap_or("{}")).unwrap_or_default(),
                })
            })
            .collect();
        result.details = Some(json!({"dom_snapshots": snapshots}));
    }
    Some(tree)
}

#[test]
fn javascript_deobfuscation_matches_the_reference_dumps_or_lists_each_difference() {
    let mut compared = Vec::new();
    let dumps = Dump::all("javascript_deobfuscation").expect("the dumps read");
    assert_eq!(dumps.len(), 9);
    for dump in dumps {
        let work = tempfile::tempdir().expect("a directory");
        let path = dump.value["input"]["observable"]["file_path"]
            .as_str()
            .expect("a path")
            .to_owned();
        let mut harness = Harness::<JavaScriptDeobfuscationAnalyzer>::new().expect("harness");
        if let Some(tree) = js_tree(&dump, &path) {
            harness = harness.tree(tree);
        }
        let observable = js_input(&harness, &dump);
        let first = harness
            .run_parser(observable.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let request = &dump.value["scanner_request"];
        let Outcome::Delay(delay) = &first else {
            // ace3's module turned it away before it asked for anything
            assert!(request.is_null(), "{}: {first:?}", dump.name);
            compared.push((
                dump.short_name().to_owned(),
                diff(
                    &dump.normal_form("JavaScriptDeobfuscationAnalysis"),
                    &normal_form(&first),
                ),
            ));
            continue;
        };
        check_js_request(&harness, &dump, delay, request);
        let (case, state) = js_case(&dump);
        let scan = match case {
            Some(case) => scan_of(&fixtures().join("js").join(case), "", state, work.path()),
            None => Scan {
                id: 1,
                scanner: "js-deobfuscator".to_owned(),
                state,
                exit_code: None,
                error: None,
                output: None,
                proxied: None,
            },
        };
        let harness = harness.scan(scan);
        let outcome = harness
            .rerun_parser(
                observable,
                harness.after_delay(delay, 1, Duration::from_secs(5)),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        match dump.short_name().rsplit('/').next().unwrap_or_default() {
            "blob_redirect.js" => {
                ace_testkit::check_view_fixture("javascript_deobfuscation_blob_redirect", &outcome);
            }
            "scripts.html.inline_0" => {
                // the trace the harness made with the snapshot: the attribute's URL, read from the DOM
                let Outcome::Done(result) = &outcome else {
                    panic!("a result")
                };
                let trace = harness.read_output(&result.files[0]).expect("the trace");
                assert!(
                    String::from_utf8_lossy(&trace).contains(
                        "window.location = \"https://evil.example.com/collect?u=victim\";"
                    )
                );
            }
            _ => {}
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("JavaScriptDeobfuscationAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed("differences.md").check(&compared, &[]) {
        panic!("{report}");
    }
}

/// The scan the first run asked for is what ace3's asked its manager for: the script under its own
/// name, its DOM snapshot beside it when it has one, and the scanner's timeout.
fn check_js_request(
    harness: &Harness<JavaScriptDeobfuscationAnalyzer>,
    dump: &Dump,
    delay: &Delay,
    request: &Value,
) {
    let scan = delay.scan.as_ref().expect("a scan");
    assert_eq!(scan.scanner, "js-deobfuscator");
    assert_eq!(
        u64::from(scan.timeout_seconds),
        request["scanner_timeout"].as_u64().expect("a timeout")
    );
    assert_eq!(
        delay.run_after.as_secs(),
        request["timeout"].as_u64().expect("a timeout")
    );
    let file_name = request["file_name"].as_str().expect("a name");
    let script = &scan.inputs[0];
    assert_eq!(
        script.name.rsplit_once('/').map(|(_, n)| n),
        Some(file_name)
    );
    assert_eq!(
        scan.args[0],
        format!("/js-deobfuscator/input/{}", script.name),
        "{}",
        dump.name
    );
    match &request["dom_snapshot"] {
        Value::Null => assert_eq!(scan.inputs.len(), 1, "{}", dump.name),
        snapshot => {
            let sidecar = &scan.inputs[1];
            assert_eq!(sidecar.name, format!("{}.dom.json", script.name));
            let bytes = std::fs::read(harness.stored(&sidecar.sha256)).expect("the snapshot");
            let written: Value = serde_json::from_slice(&bytes).expect("JSON");
            assert_eq!(&written, snapshot, "{}", dump.name);
        }
    }
}

// ---- phishkit_analyzer ----

/// The fixture each phishkit dump's scan answered with, and the state it ended in.
fn phishkit_state(case: &str) -> ScanState {
    match case {
        // the manager stopped it at its timeout, and it flushed what it had
        "url_partial" => ScanState::TimedOut,
        _ => ScanState::Completed,
    }
}

/// The tree a phishkit task's lease would hold: only its own observable, and the root's mode, which
/// the harness sends its declaration (the module doesn't read the tree).
fn phishkit_tree(dump: &Dump, observable: &ace_sdk::Observable) -> TreeView {
    // make-dumps names the mode in the label of a file's run; a URL's runs in cli mode
    let label = dump.value["input"]["label"].as_str().unwrap_or_default();
    let mode = if label.contains(" in correlation mode") {
        "correlation"
    } else {
        "cli"
    }
    .to_owned();
    TreeView {
        alert_type: None,
        analysis_mode: Some(mode),
        this: 0,
        observables: vec![TreeObservable {
            kind: observable.kind,
            value: observable.value.clone(),
            tags: Vec::new(),
            directives: observable.directives.clone(),
            detections: 0,
            paths: observable
                .path
                .iter()
                .map(|p| TreePath {
                    path: p.to_string(),
                    yara_meta: Vec::new(),
                })
                .collect(),
            size: None,
            pending: Vec::new(),
            download: None,
            relationships: Vec::new(),
        }],
        results: Vec::new(),
        truncated: false,
    }
}

/// ace-rs's normal form with ace3's job id in place of its own, which each system makes for itself.
fn with_fixed_job(form: Value, job: &str) -> Value {
    let text = serde_json::to_string(&form)
        .expect("JSON")
        .replace(job, FIXED_JOB);
    serde_json::from_str(&text).expect("JSON")
}

#[test]
fn phishkit_analyzer_matches_the_reference_dumps_or_lists_each_difference() {
    let mut compared = Vec::new();
    let dumps = Dump::all("phishkit_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 8);
    for dump in dumps {
        let work = tempfile::tempdir().expect("a directory");
        let input = &dump.value["input"];
        let harness = Harness::<PhishkitAnalyzer>::new().expect("harness");
        let observable = if input["observable"]["type"] == "file" {
            let meta: Vec<&str> = input["meta_tags"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let mut file = harness
                .file(
                    input["observable"]["file_path"].as_str().expect("a path"),
                    ace_testkit::samples_dir().join("ace-rs/web/phishkit_page.html"),
                    &meta,
                )
                .expect("the page");
            // the type the core's type step found, whose mime type the declaration reads
            if let Some(f) = file.file.as_mut() {
                f.mime_type = dump.mime_type().map(str::to_owned);
                f.facts = dump.mime_type().map(|mime| TypeFacts {
                    mime: mime.to_owned(),
                    ..TypeFacts::default()
                });
            }
            file
        } else {
            let mut url = harness.observable(
                ObservableKind::Url,
                input["observable"]["value"].as_str().expect("a value"),
            );
            for d in input["directives"].as_array().into_iter().flatten() {
                url = url.with_directive(d.as_str().expect("a directive"));
            }
            url
        };
        let harness = harness.tree(phishkit_tree(&dump, &observable));
        let first = harness
            .run_parser(observable.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let request = &dump.value["scanner_request"];
        let Outcome::Delay(delay) = &first else {
            assert!(request.is_null(), "{}: {first:?}", dump.name);
            compared.push((
                dump.short_name().to_owned(),
                diff(&dump.normal_form("PhishkitAnalysis"), &normal_form(&first)),
            ));
            continue;
        };
        let scan = delay.scan.as_ref().expect("a scan");
        assert_eq!(scan.scanner, "phishkit");
        assert_eq!(
            u64::from(scan.timeout_seconds),
            request["scanner_timeout"].as_u64().expect("a timeout")
        );
        // `delay_analysis(timeout_seconds=max(scanner_timeout, 60) * 2 + 30)`
        assert_eq!(delay.run_after.as_secs(), 150);
        let job: String = serde_json::from_value(delay.state["job"].clone()).expect("a job");
        match request["kind"].as_str() {
            Some("url") => assert_eq!(
                scan.args,
                [
                    request["target"].as_str().expect("a target").to_owned(),
                    "--output-dir".to_owned(),
                    format!("/phishkit/output/{job}"),
                ]
            ),
            _ => {
                let name = request["target"].as_str().expect("a target");
                assert_eq!(
                    scan.args,
                    [
                        "--file".to_owned(),
                        format!("/phishkit/input/{job}/{name}"),
                        "--output-dir".to_owned(),
                        format!("/phishkit/output/{job}"),
                    ]
                );
                assert_eq!(scan.inputs[0].name, format!("{job}/{name}"));
            }
        }
        let case = phishkit_case(&dump);
        let harness = harness.scan(scan_of(
            &fixtures().join("phishkit").join(case),
            // the scanner writes under its `--output-dir`, the job's directory
            &job,
            phishkit_state(case),
            work.path(),
        ));
        let outcome = harness
            .rerun_parser(
                observable,
                harness.after_delay(delay, 1, Duration::from_secs(5)),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if dump.short_name() == "url_scan" {
            ace_testkit::check_view_fixture("phishkit_url_scan", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("PhishkitAnalysis"),
                &with_fixed_job(normal_form(&outcome), &job),
            ),
        ));
    }
    if let Err(report) = listed("phishkit_differences.md").check(&compared, &[]) {
        panic!("{report}");
    }
}

/// A phishkit scan's output directory, as `scan_of` takes one: `requests.json`, its stdout and its
/// exit code.
fn phishkit_output(dir: &Path, requests: &Value, stdout: &str) {
    std::fs::create_dir_all(dir).expect("a directory");
    std::fs::write(dir.join("requests.json"), requests.to_string()).expect("written");
    std::fs::write(dir.join("std.out"), stdout).expect("written");
    std::fs::write(dir.join("exit.code"), "0").expect("written");
}

/// PLAN.md decision 64: `proxy: true` asks for the scanner pool's proxy; a scan whose main page the
/// proxy refused is scanned again direct, as ace3's manager retries it, and the result says both, in
/// its `proxy_status`, its summary and its stdout. The pool, not the module, holds the proxy: the
/// module sees it only as the pool reported it, without credentials.
#[test]
fn a_page_the_proxy_refused_is_scanned_again_direct() {
    let work = tempfile::tempdir().expect("a directory");
    let harness =
        Harness::<PhishkitAnalyzer>::with_settings(json!({ "proxy": true })).expect("harness");
    let url = "https://lure.example.net/start";
    let observable = harness
        .observable(ObservableKind::Url, url)
        .with_directive("crawl");
    let first = harness.run_parser(observable.clone()).expect("an outcome");
    let Outcome::Delay(delay) = &first else {
        panic!("{first:?}");
    };
    let scan = delay.scan.as_ref().expect("a scan");
    assert!(scan.proxy, "the first scan asks for the pool's proxy");
    assert!(
        !scan.args.iter().any(|a| a == "--proxy"),
        "the module never names it"
    );
    let job: String = serde_json::from_value(delay.state["job"].clone()).expect("a job");

    // the proxy refused the main frame's navigation; a refused image elsewhere doesn't count
    let refused = json!([
        {"type": "request", "requestId": "1", "frame_id": "main", "resource_type": "Document", "url": url},
        {"type": "request", "requestId": "2", "frame_id": "ad", "resource_type": "Document", "url": "https://ads.example.org/"},
        {"type": "error", "requestId": "2", "error_text": "net::ERR_TUNNEL_CONNECTION_FAILED", "url": "https://ads.example.org/"},
        {"type": "error", "requestId": "1", "error_text": "net::ERR_TUNNEL_CONNECTION_FAILED", "url": url},
    ]);
    let proxied_dir = work.path().join("proxied");
    phishkit_output(&proxied_dir, &refused, "loaded through the proxy\n");
    let mut proxied = scan_of(&proxied_dir, &job, ScanState::Completed, work.path());
    proxied.proxied = Some("http://proxy.example.com:3128".to_owned());
    let harness = harness.scan(proxied);
    let second = harness
        .rerun_parser(
            observable.clone(),
            harness.after_delay(delay, 1, Duration::from_secs(5)),
        )
        .expect("an outcome");
    let Outcome::Delay(retry) = &second else {
        panic!("expected a direct scan, got {second:?}");
    };
    let direct_request = retry.scan.as_ref().expect("a scan");
    assert!(!direct_request.proxy, "the retry is direct");
    assert_eq!(retry.state["job"], json!(job), "the same job");
    assert_eq!(retry.state["fallback"]["reason"], "error_pattern");

    let direct_dir = work.path().join("direct");
    let loaded = json!([
        {"type": "request", "requestId": "1", "frame_id": "main", "resource_type": "Document", "url": url},
        {"type": "response", "requestId": "1", "status_code": 200, "url": url},
    ]);
    phishkit_output(&direct_dir, &loaded, "loaded direct\n");
    let direct = scan_of(&direct_dir, &job, ScanState::Completed, work.path());
    let harness = harness.scan(direct);
    let third = harness
        .rerun_parser(
            observable,
            harness.after_delay(retry, 2, Duration::from_secs(5)),
        )
        .expect("an outcome");
    let Outcome::Done(result) = &third else {
        panic!("expected a result, got {third:?}");
    };
    let details = serde_json::to_value(&result.details).expect("details");
    assert_eq!(
        details["proxy_status"],
        json!({
            "configured": true,
            "host": "http://proxy.example.com:3128",
            "fallback_enabled": true,
            "fallback_triggered": true,
            "fallback_reason": "error_pattern",
            "fallback_details": {
                "matched_error_patterns": ["ERR_TUNNEL_CONNECTION_FAILED"],
                "failed_url": url,
            },
            "final_route": "direct",
        })
    );
    let summary = result.summary.as_deref().unwrap_or_default();
    assert!(
        summary.ends_with(" - proxy failed (error_pattern: lure.example.net), fetched direct"),
        "{summary}"
    );
    let stdout = details["stdout"].as_str().unwrap_or_default();
    assert!(
        stdout.starts_with(
            "--- PROXY ATTEMPT (failed, retried direct) ---\nloaded through the proxy"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("--- DIRECT ATTEMPT ---\nloaded direct"),
        "{stdout}"
    );
}

/// A page the proxy loaded stays proxied; with no proxy in the pool, the route is none.
#[test]
fn a_page_the_proxy_loaded_says_so_and_none_is_none() {
    for (proxied, route, configured) in [
        (Some("proxy.example.com:3128"), "proxy", true),
        (None, "none", false),
    ] {
        let work = tempfile::tempdir().expect("a directory");
        let harness =
            Harness::<PhishkitAnalyzer>::with_settings(json!({ "proxy": true })).expect("harness");
        let url = "https://lure.example.net/start";
        let observable = harness
            .observable(ObservableKind::Url, url)
            .with_directive("crawl");
        let first = harness.run_parser(observable.clone()).expect("an outcome");
        let Outcome::Delay(delay) = &first else {
            panic!("{first:?}");
        };
        let job: String = serde_json::from_value(delay.state["job"].clone()).expect("a job");
        let dir = work.path().join("out");
        phishkit_output(
            &dir,
            &json!([{"type": "response", "requestId": "1", "status_code": 200, "url": url}]),
            "loaded\n",
        );
        let mut scan = scan_of(&dir, &job, ScanState::Completed, work.path());
        scan.proxied = proxied.map(str::to_owned);
        let harness = harness.scan(scan);
        let outcome = harness
            .rerun_parser(
                observable,
                harness.after_delay(delay, 1, Duration::from_secs(5)),
            )
            .expect("an outcome");
        let Outcome::Done(result) = &outcome else {
            panic!("{outcome:?}");
        };
        let status = &serde_json::to_value(&result.details).expect("details")["proxy_status"];
        assert_eq!(status["final_route"], route);
        assert_eq!(status["configured"], configured);
        assert_eq!(status["fallback_triggered"], false);
    }
}

/// A script whose only `script.javascript` tag is file_type's runs, whatever its name: a sandbox's
/// report archive holds an inline script as both `web_requests/<…>.js` and `extracted_scripts/<sha1>.bin`,
/// one observable in ace-rs, which may be analyzed as the `.bin`. ace3 deobfuscated the `.js`.
#[test]
fn a_script_only_file_type_tags_is_deobfuscated_under_any_name() {
    let script: &[u8] =
        b"(function(){ var u = 'https://evil.example.com/x'; window.location = u; })();\n";
    let harness = Harness::<JavaScriptDeobfuscationAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details(
                "JavaScript source, ASCII text",
                "application/javascript",
            ),
        );
    let path = "sandbox/1/extracted_scripts/0123456789abcdef0123456789abcdef01234567.bin";
    let observable = harness
        .file_bytes(path, script, &["type=script.javascript"])
        .expect("the script");
    let first = harness.run_parser(observable).expect("runs");
    assert!(
        matches!(first, Outcome::Delay(_)),
        "it asks for a scan of the script: {first:?}"
    );

    // a file no module tagged and that isn't named .js is still left alone
    let harness = Harness::<JavaScriptDeobfuscationAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("data", "application/octet-stream"),
        );
    let observable = harness
        .file_bytes("sandbox/1/web_requests/blob.bin", script, &[])
        .expect("the file");
    let skipped = harness.run_parser(observable).expect("runs");
    assert!(
        matches!(&skipped, Outcome::Skipped(why) if why == "not JavaScript"),
        "{skipped:?}"
    );
}
