//! ace3's `PhishkitAnalyzer` (`saq/modules/phishkit.py`), with its client (`saq/phishkit.py`) and
//! what its manager does around the scanner (`phishkit/phishkit.py`): it loads a URL, or renders an
//! HTML or PDF file, in phishkit's Chrome, then adds the screenshots, the rendered DOM, the captured
//! requests and bodies and the downloads as files, and the URLs requested, found in the bodies, and
//! the document's own, as URLs.
//!
//! The first run asks for a scan: `scanner.py <url>` or `scanner.py --file <path>`, with
//! `--output-dir /phishkit/output/<job id>`, as the manager runs it, and the task waits as a delayed
//! task, as ace3's does with `delay_analysis`. A file goes in under the extension libmagic's type for
//! it has, as the manager renames it (`_correct_file_extension`), from the type the core's libmagic
//! gave it. The next run reads the output.
//!
//! What differs from ace3:
//! - The proxy (PLAN.md decision 64): ace3's `proxy` names a proxy configuration its manager holds;
//!   here `proxy: true` asks for the scanner pool's, `ACE_RS_PHISHKIT_PROXY`, which the pool adds as
//!   the scanner's `--proxy`, so its credentials never reach the module or a row. ace3's manager
//!   reads the scanner's `requests.json` to decide whether to try again without the proxy; the pool
//!   reads nothing a scanner writes, so here this module decides on its next run, with ace3's rule
//!   (`fallback_reason`) and `phishkit_config.yaml`'s `proxy_fallback`, which are its settings, and
//!   asks for a direct scan of the same job. `proxy_status` is what ace3's `proxy.json` says, and
//!   the stdout holds both attempts, as ace3's does.
//! - The manager's `--config` is a copy of `etc/phishkit_config.yaml`; here the scanner reads the copy
//!   its image was built with, `/opt/app/phishkit_config.yaml`, which is the same file. An analyst's edit
//!   to it reaches the scanner when the image is built again. `deny_crawl_url_patterns`, the one part
//!   the module reads, is the module's setting.
//! - Its metrics go to no fluent-bit (`fluent_bit_metrics_enabled`).
//! - Its results are kept in the analysis cache for ace3's 6 hours (`Module::CACHE`), keyed on the
//!   observable's value, its settings (where ace3 keys the content of its scanner config, whose one
//!   part the module reads is `deny_crawl_url_patterns`) and the id of the image its scan's
//!   container ran (`Cache::scanners`, ace3's `scanner_image`). What it reads to decide whether it
//!   runs (a file's render directive or role, the root's mode, its extension and its type's mime
//!   type) is its declaration's, which a hit is checked against first. A failed scan is a result
//!   with an error, which isn't kept; a partial scan is kept, as ace3 keeps one. As in ace3, a file's
//!   result is keyed on its bytes alone, so a hit for a file in another alert names the first
//!   file's path in `scan_result` and the scanner saw the first file's name, as ace3's replayed
//!   result does. Its files are under `phishkit/<job id>/`, named after the observable
//!   (`CachePaths::Under`), so a hit puts them where a run would.
//! - It doesn't wait for `file_type` (ace3's declared dependency): its declaration reads the file's
//!   type, which the core finds before any other task on a file (PLAN.md decision 25), so the
//!   dependency added nothing for a file, and for a URL it kept the module from running at all,
//!   where ace3 counts a dependency that doesn't take the observable as met.
//! - `output_dir` is the scan's directory in the alert, `phishkit/<job id>`, where ace3 names a
//!   temporary directory on its node; `job_id` is made from the module and the observable (`crate::job_id`).
//! - ace3 walks the output directory in the order the filesystem lists it; here a directory's files
//!   are sorted by name (`crate::read_output`).
//! - ace3's manager reads the scanner's stdout and stderr as UTF-8 and fails on bytes that aren't;
//!   here they read as U+FFFD.

use std::time::Duration;

use ace_pycompat::pystr;
use ace_results::FileRole;
use ace_results::types::scanners::PhishkitAnalysis;
use ace_results::{
    AlertPath, AnalysisType, NewObservable, ObservableKind, ObservableRef, Relationship,
    RelationshipKind, ResultEnvelope,
};
use ace_sdk::cache::{Cache, CachePaths};
use ace_sdk::scanners::{PHISHKIT, ScanInput, ScanRequest, ScanState};
use ace_sdk::takes::{Case, Condition, Match, Takes, Text};
use ace_sdk::{Delay, Module, ModuleError, Observable, Outcome, Parser, Resources, TaskContext};
use ace_urlfinder::{Finder, Magic, Url};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::js::truthy;
use crate::{ScanOutput, read_output, text, text_ignoring};

const CRAWL: &str = "crawl";
const RENDER: &str = "render";
const EXTRACT_URLS: &str = "extract_urls";
const SCAN_TYPE_URL: &str = "url";
const SCAN_TYPE_FILE: &str = "file";
/// `OCR_SKIP_CONTENT_TYPES`: a screenshot of Chrome showing one of these as text tells OCR nothing.
const OCR_SKIP_CONTENT_TYPES: &[&str] = &[
    "application/javascript",
    "application/json",
    "application/x-javascript",
    "application/xml",
    "text/css",
    "text/javascript",
    "text/plain",
    "text/xml",
];
/// `SCREENSHOT_PREFIXES`.
const SCREENSHOT_PREFIXES: &[&str] = &["screenshot.png", "pre_bypass_screenshot"];
const TOP_LEVEL_SCRIPT_NAME: &str = "script.js";
const DOM_NAME: &str = "dom.html";
const RESPONSE_BODIES_NAME: &str = "response_bodies.txt";
const REQUESTS_NAME: &str = "requests.json";
/// The files the manager writes beside the scanner's, which the module reads and doesn't add.
const MANAGER_FILES: &[&str] = &[
    "exit.code",
    "std.out",
    "std.err",
    "metrics.json",
    "proxy.json",
];

/// ace3's `analysis_module_phishkit_analyzer` settings, less the fluent-bit and proxy ones.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PhishkitSettings {
    /// The extensions of files rendered, lowercased with their dot.
    pub valid_file_extensions: Vec<String>,
    /// The libmagic types of files rendered, as file_type gives them.
    pub valid_mime_types: Vec<String>,
    /// How long the scanner may run, in seconds.
    pub scanner_timeout: u32,
    /// ace3's `proxy`: scan through the scanner pool's proxy (`ACE_RS_PHISHKIT_PROXY`), when the
    /// pool has one. ace3 ships none.
    pub proxy: bool,
    /// `proxy_fallback_to_direct`: retry a proxied scan direct when the proxy kept the page from
    /// loading.
    pub proxy_fallback_to_direct: bool,
    /// `phishkit_config.yaml`'s `proxy_fallback.error_patterns`: Chrome's errors that mean the
    /// proxy refused the page itself.
    pub proxy_error_patterns: Vec<String>,
    /// `proxy_fallback.proxy_status_codes`: the main page's status codes that mean the proxy refused
    /// it.
    pub proxy_status_codes: Vec<i64>,
    /// `proxy_fallback.retry_on_timeout`: a proxied scan that timed out is retried direct.
    pub proxy_retry_on_timeout: bool,
    /// URLs it won't load: any that contains one of these, ignoring case, as
    /// `etc/phishkit_config.yaml`'s `deny_crawl_url_patterns`.
    pub deny_crawl_url_patterns: Vec<String>,
}

impl Default for PhishkitSettings {
    /// ace3's `etc/saq.default.yaml` and `etc/phishkit_config.yaml`.
    fn default() -> Self {
        PhishkitSettings {
            valid_file_extensions: vec![".html".to_owned(), ".htm".to_owned(), ".pdf".to_owned()],
            valid_mime_types: vec!["text/html".to_owned(), "application/pdf".to_owned()],
            scanner_timeout: 30,
            proxy: false,
            proxy_fallback_to_direct: true,
            proxy_error_patterns: [
                "ERR_TUNNEL_CONNECTION_FAILED",
                "ERR_PROXY_CONNECTION_FAILED",
                "ERR_PROXY_AUTH_FAILED",
                "ERR_PROXY_CERTIFICATE_INVALID",
            ]
            .map(str::to_owned)
            .to_vec(),
            proxy_status_codes: vec![400, 403, 407, 500, 502, 504, 522],
            proxy_retry_on_timeout: true,
            deny_crawl_url_patterns: Vec::new(),
        }
    }
}

/// What the first run leaves for the next.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Waiting {
    job: String,
    scan_type: String,
    /// Set on the direct scan that retries a proxied one.
    #[serde(default)]
    fallback: Option<Fallback>,
}

/// Why a proxied scan was retried direct, and what it said, for `proxy_status` and the stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Fallback {
    reason: String,
    details: Value,
    /// The proxy, without its credentials, as the pool reported it.
    proxy: String,
    timed_out: bool,
    /// The proxied attempt's stdout, at most `MAX_PROXY_STDOUT` bytes.
    stdout: String,
}

/// The most of a proxied attempt's stdout kept beside the direct one's.
const MAX_PROXY_STDOUT: usize = 64 * 1024;

/// The phishkit_analyzer module.
pub struct PhishkitAnalyzer {
    magic: Result<Vec<u8>, String>,
}

impl Module for PhishkitAnalyzer {
    const NAME: &'static str = PhishkitAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Url, ObservableKind::File];
    /// `custom_requirement`: a URL needs `crawl`, which other modules add later, so the core queues
    /// the module when it lands. A file needs `render` or the `email.attachment` type, which it has
    /// from the start.
    const REQUIRED_DIRECTIVES_BY_KIND: &'static [(ObservableKind, &'static [&'static str])] =
        &[(ObservableKind::Url, &[CRAWL])];
    const SCANNERS: &'static [&'static str] = &[PHISHKIT.name];
    /// ace3's `cache_ttl` of 6 hours (the module's docs).
    const CACHE: Option<Cache> = Some(Cache {
        paths: CachePaths::Under(phishkit_dir),
        scanners: &[PHISHKIT.name],
        ..Cache::new(1, Duration::from_secs(6 * 3600))
    });
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 2048,
        cpu_seconds: 240,
    };
    type Output = PhishkitAnalysis;
    type Settings = PhishkitSettings;

    fn init(_: &PhishkitSettings) -> Result<Self, ModuleError> {
        Ok(PhishkitAnalyzer {
            magic: std::fs::read(ace_urlfinder::magic::DATABASE).map_err(|e| e.to_string()),
        })
    }

    fn takes(settings: &PhishkitSettings) -> Takes {
        // `custom_requirement` for a file; a URL's crawl directive is REQUIRED_DIRECTIVES_BY_KIND's,
        // and its deny patterns read the URL, which `analyze` does
        let for_a_file = |condition: Condition| {
            Condition::Any(vec![
                Condition::Kind(vec![ObservableKind::File]).negated(),
                condition,
            ])
        };
        let strings = |items: &[String]| Match::OneOf(items.to_vec());
        Takes::everything()
            .and(
                for_a_file(Condition::Any(vec![
                    Condition::directive(RENDER),
                    Condition::yara_meta("type", "email.attachment"),
                ])),
                "no render directive",
            )
            .and(
                for_a_file(Condition::Mode("correlation".to_owned())),
                "files render only in correlation mode",
            )
            .and(for_a_file(Condition::not_empty()), "an empty file")
            // `_file_scan_enabled`: the file's extension, lowered, or file_type's mime type, which
            // is the type's, is one the module renders
            .and(
                for_a_file(Condition::Any(vec![
                    Condition::Extension(Text::new(
                        strings(&settings.valid_file_extensions),
                        Case::Lower,
                    )),
                    Condition::Mime(Text::exact(strings(&settings.valid_mime_types))),
                ])),
                "not a type phishkit renders",
            )
    }
}

impl Parser for PhishkitAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<PhishkitSettings>,
    ) -> Result<Outcome<PhishkitAnalysis>, ModuleError> {
        if let Some(why) = refusal(ctx)? {
            return Ok(Outcome::Skipped(why));
        }
        match (ctx.scan(), ctx.delay_state::<Waiting>()?) {
            (Some(_), Some(waiting)) => self.finish(ctx, &waiting),
            _ => start(ctx, ctx.settings().proxy, None),
        }
    }
}

/// Why `custom_requirement` or `execute_analysis` turns the observable away, if it does.
fn refusal(ctx: &TaskContext<PhishkitSettings>) -> Result<Option<String>, ModuleError> {
    let observable = ctx.observable();
    let settings = ctx.settings();
    if observable.kind == ObservableKind::Url {
        {
            if !observable.has_directive(CRAWL) {
                return Ok(Some("no crawl directive".to_owned()));
            }
            let lower = pystr::lower(&observable.value);
            if let Some(pattern) = settings
                .deny_crawl_url_patterns
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| pystr::lower(p))
                .find(|p| lower.contains(p.as_ref()))
            {
                return Ok(Some(format!("matched deny pattern {pattern:?}")));
            }
            Ok(None)
        }
    } else if observable.kind == ObservableKind::File {
        // what a file needs is in `takes`
        Ok(None)
    } else {
        Ok(Some("not a URL or a file".to_owned()))
    }
}

/// The directory the module puts an observable's files under, `phishkit/<job id>/`, which follows
/// from the observable alone (`CachePaths::Under`).
pub fn phishkit_dir(kind: ObservableKind, value: &str) -> String {
    format!(
        "phishkit/{}/",
        crate::job_id_of(PhishkitAnalysis::MODULE, kind, value)
    )
}

/// `os.path.splitext(name)`: the name and its last extension, with its dot; a leading dot isn't one.
fn splitext(name: &str) -> (&str, &str) {
    let start = name.len() - name.trim_start_matches('.').len();
    match name[start..].rfind('.') {
        Some(dot) => name.split_at(start + dot),
        None => (name, ""),
    }
}

/// `_correct_file_extension`: the name a file renders under, with the extension its type has,
/// unless it already has it, or libmagic says only `text/plain` of a name with an extension.
pub fn corrected_name(name: &str, mime: Option<&str>) -> String {
    let Some(mime) = mime.filter(|m| !m.is_empty()) else {
        return name.to_owned();
    };
    let (stem, existing) = splitext(name);
    if mime == "text/plain" && !existing.is_empty() {
        return name.to_owned();
    }
    let Some(extension) = crate::mimetypes::guess_extension(mime) else {
        return name.to_owned();
    };
    if pystr::lower(name).ends_with(pystr::lower(extension).as_ref()) {
        return name.to_owned();
    }
    format!("{stem}{extension}")
}

/// `str(observable)`: `type(value)`, or a file's path.
fn py_str(observable: &Observable) -> String {
    match &observable.path {
        Some(path) => path.to_string(),
        None => match observable.time {
            Some(time) => format!(
                "{}({}@{})",
                observable.kind,
                observable.value,
                time.format("%Y-%m-%d %H:%M:%S%:z")
            ),
            None => format!("{}({})", observable.kind, observable.value),
        },
    }
}

/// The first run: the scan, as the manager's `scan_url` and `scan_file` run the scanner, through the
/// pool's proxy when `proxied`. A direct retry of a proxied scan (`fallback`) scans the same job again.
fn start(
    ctx: &TaskContext<PhishkitSettings>,
    proxied: bool,
    fallback: Option<Fallback>,
) -> Result<Outcome<PhishkitAnalysis>, ModuleError> {
    let observable = ctx.observable();
    let settings = ctx.settings();
    let job = crate::job_id(ctx, PhishkitAnalysis::MODULE);
    let timeout = Duration::from_secs(u64::from(settings.scanner_timeout));
    let mut request = ScanRequest::new(PHISHKIT.name, timeout);
    let scan_type = if observable.kind == ObservableKind::Url {
        // the scanner's argparse would read a value starting with '-' as an option
        if observable.value.starts_with('-') {
            return Ok(Outcome::Skipped(
                "a URL the scanner would read as an option".to_owned(),
            ));
        }
        request = request.arg(observable.value.clone());
        SCAN_TYPE_URL
    } else {
        let file = ctx.input_file()?;
        let name = corrected_name(file.name(), file.mime_type.as_deref());
        let input = format!("{job}/{name}");
        request = request
            .arg("--file")
            .arg(format!("{}/{input}", PHISHKIT.input_dir))
            .input(ScanInput {
                name: input,
                sha256: file.sha256,
                size: file.size,
            });
        SCAN_TYPE_FILE
    };
    request = request
        .arg("--output-dir")
        .arg(format!("{}/{job}", PHISHKIT.output_dir));
    if proxied {
        request = request.through_proxy();
    }
    // `delay_analysis(timeout_seconds=max(scanner_timeout, 60) * 2 + 30)`
    let wait = Duration::from_secs(u64::from(settings.scanner_timeout.max(60)) * 2 + 30);
    let delay = Delay::new(wait, wait + Duration::from_secs(1))
        .with_state(&Waiting {
            job,
            scan_type: scan_type.to_owned(),
            fallback,
        })?
        .with_scan(request);
    Ok(Outcome::Delay(delay))
}

/// The URLs a result adds, each once, in the order first added, with the last display type given.
#[derive(Default)]
struct Urls {
    urls: Vec<NewObservable>,
}

impl Urls {
    fn add(&mut self, value: &str, display_type: &str) {
        match self.urls.iter_mut().find(|o| o.value == value) {
            Some(known) => known.display_type = Some(display_type.to_owned()),
            None => {
                let mut observable = NewObservable::new(ObservableKind::Url, value);
                observable.display_type = Some(display_type.to_owned());
                self.urls.push(observable);
            }
        }
    }
}

impl PhishkitAnalyzer {
    /// `continue_analysis`.
    fn finish(
        &self,
        ctx: &TaskContext<PhishkitSettings>,
        waiting: &Waiting,
    ) -> Result<Outcome<PhishkitAnalysis>, ModuleError> {
        let observable = ctx.observable();
        let scan = ctx.scan().ok_or_else(|| ModuleError::other("no scan"))?;
        let mut result = ResultEnvelope::new(PhishkitAnalysis {
            output_dir: Some(format!("phishkit/{}", waiting.job)),
            job_id: Some(waiting.job.clone()),
            scan_type: Some(waiting.scan_type.clone()),
            ..Default::default()
        });
        let failed = |result: &mut ResultEnvelope<PhishkitAnalysis>, why: &str| {
            result.error = Some(format!(
                "phishkit scan failed for {} job ID {}: {why}",
                py_str(observable),
                waiting.job
            ));
        };
        let mut output = match scan.state {
            // the engine's delay ran out first, and nothing more comes back
            ScanState::Pending => return Ok(done(result)),
            ScanState::Failed | ScanState::Abandoned | ScanState::Cancelled => {
                failed(
                    &mut result,
                    scan.error.as_deref().unwrap_or(scan.state.as_str()),
                );
                return Ok(done(result));
            }
            ScanState::Completed | ScanState::TimedOut => {
                let archive = scan
                    .output
                    .as_ref()
                    .ok_or_else(|| ModuleError::other("the scan brought nothing back"))?;
                read_output(ctx, archive, &|path| {
                    matches!(
                        path.rsplit('/').next(),
                        Some("metrics.json" | REQUESTS_NAME | RESPONSE_BODIES_NAME)
                    )
                })?
            }
        };
        // the scanner's `--output-dir` is the job's directory under the one that comes back
        let job_dir = format!("{}/", waiting.job);
        output
            .files
            .retain_mut(|f| match f.path.strip_prefix(&job_dir) {
                Some(path) => {
                    f.path = path.to_owned();
                    true
                }
                None => false,
            });
        let stdout = text(&output.stdout);
        let stderr = text(&output.stderr);
        // ace3's manager retries a proxied scan direct when the proxy kept the page from loading
        let settings = ctx.settings();
        if waiting.fallback.is_none()
            && settings.proxy_fallback_to_direct
            && let Some(proxy) = &scan.proxied
            && let Some((reason, details)) =
                fallback_reason(settings, scan.state, &output, &stdout, &stderr)
        {
            tracing::warn!(
                job = %waiting.job,
                %reason,
                failed_url = ?details.get("failed_url"),
                "the proxied phishkit scan failed through the proxy; scanning it again direct"
            );
            let mut kept = stdout.clone();
            if kept.len() > MAX_PROXY_STDOUT {
                let mut at = MAX_PROXY_STDOUT;
                while !kept.is_char_boundary(at) {
                    at -= 1;
                }
                kept.truncate(at);
            }
            return start(
                ctx,
                false,
                Some(Fallback {
                    reason,
                    details,
                    proxy: proxy.clone(),
                    timed_out: scan.state == ScanState::TimedOut,
                    stdout: kept,
                }),
            );
        }
        // ace3's std.out after a retry: both attempts
        let stdout = match &waiting.fallback {
            Some(fallback) => format!(
                "--- PROXY ATTEMPT ({}, retried direct) ---\n{}\n--- DIRECT ATTEMPT ---\n{stdout}",
                if fallback.timed_out {
                    "timed out"
                } else {
                    "failed"
                },
                fallback.stdout
            ),
            None => stdout,
        };
        let exit_code = scan.exit_code.map(i64::from);
        // scan_url raises when the scanner failed and left nothing to harvest
        if waiting.scan_type == SCAN_TYPE_URL
            && exit_code != Some(0)
            && output.at(REQUESTS_NAME).is_none()
            && output.at(DOM_NAME).is_none()
        {
            failed(&mut result, &format!("scan failed: {stderr}"));
            return Ok(done(result));
        }
        self.harvest(ctx, waiting, &output, stdout, stderr, exit_code, result)
    }

    /// What `continue_analysis` does with a scan's files, once they're back.
    #[allow(clippy::too_many_arguments)]
    fn harvest(
        &self,
        ctx: &TaskContext<PhishkitSettings>,
        waiting: &Waiting,
        output: &ScanOutput,
        stdout: String,
        stderr: String,
        exit_code: Option<i64>,
        mut result: ResultEnvelope<PhishkitAnalysis>,
    ) -> Result<Outcome<PhishkitAnalysis>, ModuleError> {
        let observable = ctx.observable();
        // the results are in, possibly partial: phishkit.py clears the error here
        result.error = None;
        let details = &mut result.details;
        details.exit_code = exit_code;
        details.stdout = Some(stdout);
        details.stderr = Some(stderr);
        // what the manager writes to proxy.json: the proxy is configured when the pool had one for
        // the first attempt
        let fallback = waiting.fallback.as_ref();
        let proxy = fallback
            .map(|f| f.proxy.clone())
            .or_else(|| ctx.scan().and_then(|s| s.proxied.clone()));
        details.proxy_status = Some(json!({
            "configured": proxy.is_some(),
            "host": proxy,
            "fallback_enabled": ctx.settings().proxy_fallback_to_direct,
            "fallback_triggered": fallback.is_some(),
            "fallback_reason": fallback.map(|f| f.reason.clone()),
            "fallback_details": fallback.map_or_else(|| json!({}), |f| f.details.clone()),
            "final_route": match (fallback, &proxy) {
                (Some(_), _) => "direct",
                (None, Some(_)) => "proxy",
                (None, None) => "none",
            },
        }));
        let skip_screenshot_ocr = top_level_content_type(output)
            .is_some_and(|t| OCR_SKIP_CONTENT_TYPES.contains(&t.as_str()));
        let mut dom: Option<usize> = None;
        for file in &output.files {
            let name = file.name();
            if name == "metrics.json" {
                // json.load, whose failure ace3 logs and passes over
                let bytes = file.bytes.as_deref().unwrap_or_default();
                if let Ok(text) = std::str::from_utf8(bytes)
                    && let Some(metrics) = crate::json_loads(text)
                {
                    details.metrics = Some(metrics);
                }
                continue;
            }
            if MANAGER_FILES.contains(&name) {
                continue;
            }
            let path = format!("phishkit/{}/{}", waiting.job, file.path);
            let Ok(path) = AlertPath::new(&path) else {
                continue;
            };
            let mut new_file = file.file.clone();
            new_file.path = path;
            new_file.set_role(FileRole::DOCUMENT_HTML_PHISHKIT);
            new_file.exclude_modules.extend([
                PhishkitAnalysis::MODULE.to_owned(),
                "pdf_analyzer".to_owned(),
            ]);
            if skip_screenshot_ocr && SCREENSHOT_PREFIXES.iter().any(|p| name.starts_with(p)) {
                new_file.exclude_modules.push("ocr".to_owned());
            }
            if name == RESPONSE_BODIES_NAME {
                new_file
                    .exclude_modules
                    .push("html_js_extraction".to_owned());
            }
            if name == TOP_LEVEL_SCRIPT_NAME {
                new_file.directives.push(EXTRACT_URLS.to_owned());
            }
            if name == DOM_NAME {
                dom = Some(result.files.len());
            }
            details.output_files.push(new_file.path.to_string());
            result.files.push(new_file);
        }

        let interrupted = match &details.metrics {
            Some(Value::Object(metrics)) => metrics.get("interrupted").is_some_and(truthy),
            Some(other) if truthy(other) => {
                return Err(ModuleError::other(format!(
                    "'{}' object has no attribute 'get'",
                    crate::js::py_type(other)
                )));
            }
            _ => false,
        } || details.exit_code == Some(143);
        details.scan_result = Some(if interrupted {
            format!("partial scan of {}: scanner timed out", py_str(observable))
        } else {
            format!("successfully scanned {}", py_str(observable))
        });

        let scanned = (observable.kind == ObservableKind::Url)
            .then(|| Url::new(&observable.value).value().to_owned());
        let scanned = scanned.as_deref();
        let mut urls = Urls::default();
        marker_urls(output, scanned, &mut urls);
        request_urls(output, scanned, &mut urls);
        self.captured_urls(ctx, output, scanned, &mut urls)?;
        if let Some(dom) = dom {
            let metrics = result.details.metrics.clone();
            if let Some(target) = document_url(metrics.as_ref(), scanned, observable, &mut urls) {
                result.files[dom]
                    .relationships
                    .push(Relationship::new(RelationshipKind::DownloadedFrom, target));
            }
        }
        result.observables.extend(urls.urls);
        Ok(done(result))
    }

    /// `_extract_urls_from_captured_bodies`: urlfinderlib over each body in the corpus.
    fn captured_urls(
        &self,
        ctx: &TaskContext<PhishkitSettings>,
        output: &ScanOutput,
        scanned: Option<&str>,
        urls: &mut Urls,
    ) -> Result<(), ModuleError> {
        let Some(bodies) = output.at(RESPONSE_BODIES_NAME) else {
            return Ok(());
        };
        let corpus = text_ignoring(bodies.bytes.as_deref().unwrap_or_default());
        let database = self
            .magic
            .as_ref()
            .map_err(|e| ModuleError::other(e.clone()))?;
        let magic = Magic::load(database.clone()).map_err(ModuleError::other)?;
        let finder = Finder::new(&magic);
        for body in split_bodies(&corpus) {
            ctx.check_cancelled()?;
            if pystr::strip(body).is_empty() {
                continue;
            }
            // a body that won't parse doesn't fail the analysis
            let Ok(found) = finder.find_urls(body.as_bytes(), "", "text/plain", false) else {
                continue;
            };
            for raw in found {
                if raw.starts_with("file:///")
                    || raw.starts_with("data:")
                    || raw.starts_with("blob:")
                {
                    continue;
                }
                let url = Url::new(&raw);
                if url.value().is_empty() || Some(url.value()) == scanned {
                    continue;
                }
                urls.add(url.value(), "Phishkit Captured URL");
            }
        }
        Ok(())
    }
}

/// `_top_level_content_type`: the type of the first response in requests.json that isn't a
/// redirect, lowercased without its parameters.
fn top_level_content_type(output: &ScanOutput) -> Option<String> {
    let entries = requests(output)?;
    let entries = entries.as_array()?;
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        if entry.get("type").and_then(Value::as_str) != Some("response") {
            continue;
        }
        if let Some(code) = entry.get("status_code").and_then(Value::as_i64)
            && entry
                .get("status_code")
                .is_some_and(|c| c.is_i64() || c.is_u64())
            && (300..400).contains(&code)
        {
            continue;
        }
        let headers = entry.get("headers")?.as_object()?;
        for (name, value) in headers {
            if pystr::lower(name) == "content-type"
                && let Some(value) = value.as_str()
            {
                let first = value.split(';').next().unwrap_or_default();
                return Some(pystr::lower(pystr::strip(first)).into_owned());
            }
        }
        return None;
    }
    None
}

/// requests.json, read as ace3 reads it: `errors="ignore"`, then `json.load`.
fn requests(output: &ScanOutput) -> Option<Value> {
    let file = output.at(REQUESTS_NAME)?;
    let text = text_ignoring(file.bytes.as_deref().unwrap_or_default());
    crate::json_loads(&text)
}

/// ace3's manager's reasons to retry a proxied scan direct, in its order: a timeout, when
/// `proxy_retry_on_timeout`; else a main-frame navigation that failed with one of the proxy's errors
/// (`_proxy_navigation_failure`); else a main page answered with one of the proxy's status codes
/// (`_matched_proxy_status_code`). The reason and its details, or None.
fn fallback_reason(
    settings: &PhishkitSettings,
    state: ScanState,
    output: &ScanOutput,
    stdout: &str,
    stderr: &str,
) -> Option<(String, Value)> {
    if state == ScanState::TimedOut {
        return settings
            .proxy_retry_on_timeout
            .then(|| ("timeout".to_owned(), json!({})));
    }
    let requests = requests(output);
    if let Some(details) = navigation_failure(
        requests.as_ref(),
        stdout,
        stderr,
        &settings.proxy_error_patterns,
    ) {
        return Some(("error_pattern".to_owned(), details));
    }
    let code = main_status(requests.as_ref(), &settings.proxy_status_codes)?;
    Some((
        "status_code".to_owned(),
        json!({ "matched_status_code": code }),
    ))
}

/// `_proxy_navigation_failure`: the failed navigation of the main frame, the frame of the first
/// Document request, whose error is one of `patterns`, with the patterns it matched and its URL.
/// Without a `requests.json` that records resource types, stdout and stderr are matched instead.
fn navigation_failure(
    requests: Option<&Value>,
    stdout: &str,
    stderr: &str,
    patterns: &[String],
) -> Option<Value> {
    if patterns.is_empty() {
        return None;
    }
    let entries = requests.and_then(Value::as_array).filter(|entries| {
        entries.iter().any(|e| {
            e.get("type").and_then(Value::as_str) == Some("request")
                && e.get("resource_type").is_some()
        })
    });
    let Some(entries) = entries else {
        let combined = format!("{stdout}{stderr}");
        let matched: Vec<&String> = patterns
            .iter()
            .filter(|p| combined.contains(p.as_str()))
            .collect();
        return (!matched.is_empty()).then(|| json!({ "matched_error_patterns": matched }));
    };
    let mut main_frame: Option<&Value> = None;
    let mut navigations: Vec<(&Value, &Value)> = Vec::new();
    for e in entries {
        if e.get("type").and_then(Value::as_str) == Some("request")
            && e.get("resource_type").and_then(Value::as_str) == Some("Document")
        {
            let frame = e.get("frame_id").unwrap_or(&Value::Null);
            if main_frame.is_none() {
                main_frame = Some(frame);
            }
            let id = e.get("requestId").unwrap_or(&Value::Null);
            // a later request with the same id replaces the first, as ace3's dict does
            navigations.retain(|(known, _)| *known != id);
            navigations.push((id, e));
        }
    }
    for e in entries {
        if e.get("type").and_then(Value::as_str) != Some("error") {
            continue;
        }
        let error_text = e.get("error_text").and_then(Value::as_str).unwrap_or("");
        let matched: Vec<&String> = patterns
            .iter()
            .filter(|p| error_text.contains(p.as_str()))
            .collect();
        if matched.is_empty() {
            continue;
        }
        let id = e.get("requestId").unwrap_or(&Value::Null);
        let Some((_, navigation)) = navigations.iter().find(|(known, _)| *known == id) else {
            continue;
        };
        if Some(navigation.get("frame_id").unwrap_or(&Value::Null)) != main_frame {
            continue;
        }
        let failed_url = e
            .get("url")
            .filter(|u| truthy(u))
            .or_else(|| navigation.get("url"))
            .cloned()
            .unwrap_or(Value::Null);
        return Some(json!({ "matched_error_patterns": matched, "failed_url": failed_url }));
    }
    None
}

/// `_matched_proxy_status_code`: the first response's status code, when it's one of `codes`.
fn main_status(requests: Option<&Value>, codes: &[i64]) -> Option<i64> {
    if codes.is_empty() {
        return None;
    }
    let first = requests?
        .as_array()?
        .iter()
        .find(|e| e.get("type").and_then(Value::as_str) == Some("response"))?;
    let code = first.get("status_code").and_then(Value::as_i64)?;
    codes.contains(&code).then_some(code)
}

/// Python's `urlparse(url).netloc`: what follows `//` up to the path, query or fragment, or None
/// when it's empty.
fn netloc(url: &str) -> Option<&str> {
    let rest = url.split_once("//")?.1;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end]).filter(|n| !n.is_empty())
}

/// The MARKER URL lines of the bodies corpus.
fn marker_urls(output: &ScanOutput, scanned: Option<&str>, urls: &mut Urls) {
    let Some(bodies) = output.at(RESPONSE_BODIES_NAME) else {
        return;
    };
    let corpus = text_ignoring(bodies.bytes.as_deref().unwrap_or_default());
    for line in corpus.split_inclusive('\n') {
        let line = pystr::strip(line);
        // re.match(r"MARKER URL: (.+)$", line)
        let Some(rest) = line.strip_prefix("MARKER URL: ") else {
            continue;
        };
        if rest.is_empty() || rest.contains('\n') {
            continue;
        }
        let url = Url::new(pystr::strip(rest));
        if !url.value().is_empty()
            && Some(url.value()) != scanned
            && !url.value().starts_with("file:///")
        {
            urls.add(url.value(), "Phishkit Request URL");
        }
    }
}

/// Each request's URL in requests.json. ace3 stops at an entry it can't read, keeping what it added.
fn request_urls(output: &ScanOutput, scanned: Option<&str>, urls: &mut Urls) {
    let Some(entries) = requests(output) else {
        return;
    };
    // iterating a dict gives its keys, and a string its characters: neither has `get`
    let Some(entries) = entries.as_array() else {
        return;
    };
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return;
        };
        if entry.get("type").is_none_or(|t| t != "request") {
            continue;
        }
        let Some(raw) = entry.get("url").filter(|u| truthy(u)) else {
            continue;
        };
        let Some(raw) = raw.as_str() else {
            return;
        };
        if raw.starts_with("file:///") || raw.starts_with("data:") || raw.starts_with("blob:") {
            continue;
        }
        let url = Url::new(raw);
        if url.value().is_empty() || Some(url.value()) == scanned {
            continue;
        }
        urls.add(url.value(), "Phishkit Request URL");
    }
}

/// `re.split(r"\n\nMARKER URL: \S+\n\n", corpus)`.
fn split_bodies(corpus: &str) -> Vec<&str> {
    const MARK: &str = "\n\nMARKER URL: ";
    let mut bodies = Vec::new();
    let mut start = 0;
    let mut from = 0;
    while let Some(found) = corpus[from..].find(MARK) {
        let at = from + found;
        let after = at + MARK.len();
        let run = corpus[after..]
            .char_indices()
            .find(|(_, c)| pystr::is_space(*c))
            .map_or(corpus.len() - after, |(i, _)| i);
        if run > 0 && corpus[after + run..].starts_with("\n\n") {
            bodies.push(&corpus[start..at]);
            start = after + run + 2;
            from = start;
        } else {
            from = at + 1;
        }
    }
    bodies.push(&corpus[start..]);
    bodies
}

/// `_link_document_url`: the URL dom.html was loaded from, as the browser had it after every
/// redirect, which is the scanned URL or one the result adds.
fn document_url(
    metrics: Option<&Value>,
    scanned: Option<&str>,
    observable: &Observable,
    urls: &mut Urls,
) -> Option<ObservableRef> {
    let document = metrics?.as_object()?.get("document_url")?.as_str()?;
    let lower = pystr::lower(document);
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return None;
    }
    let url = Url::new(document);
    if url.value().is_empty() {
        return None;
    }
    if Some(url.value()) == scanned {
        return Some(ObservableRef::new(observable.kind, &observable.value));
    }
    urls.add(url.value(), "Phishkit Document URL");
    Some(ObservableRef::new(ObservableKind::Url, url.value()))
}

/// The result, with ace3's `generate_summary`.
fn done(mut result: ResultEnvelope<PhishkitAnalysis>) -> Outcome<PhishkitAnalysis> {
    result.error = result.error.take().filter(|e| !e.trim().is_empty());
    result.summary = Some(summary(&result.details, result.error.as_deref()));
    Outcome::Done(result)
}

/// `generate_summary`, with the result's error.
pub fn summary(details: &PhishkitAnalysis, error: Option<&str>) -> String {
    const NAME: &str = "Phishkit Analysis";
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        return format!("{NAME}: failed: {error}");
    }
    let unfinished = details.job_id.is_some()
        && matches!(
            details.scan_type.as_deref(),
            Some(SCAN_TYPE_URL | SCAN_TYPE_FILE)
        )
        && details.scan_result.is_none()
        && details.exit_code.is_none()
        && details.output_files.is_empty();
    if unfinished {
        return format!("{NAME}: scan timed out — no content captured");
    }
    if !matches!(
        details.scan_type.as_deref(),
        Some(SCAN_TYPE_URL | SCAN_TYPE_FILE)
    ) {
        return format!("{NAME}: completed");
    }
    let mut summary = format!(
        "{NAME}: output files created ({})",
        crate::format_item_list_for_summary(&details.output_files)
    );
    let metrics: Option<&Map<String, Value>> = details.metrics.as_ref().and_then(Value::as_object);
    if metrics
        .and_then(|m| m.get("interrupted"))
        .is_some_and(truthy)
        || details.exit_code == Some(143)
    {
        summary.push_str(" - PARTIAL (scanner timed out)");
    }
    if let Some(bytes) = metrics
        .and_then(|m| m.get("total_bytes_downloaded"))
        .filter(|b| truthy(b))
        .and_then(Value::as_f64)
    {
        summary.push_str(&format!(
            " - {:.2} MB downloaded",
            bytes / (1024.0 * 1024.0)
        ));
    }
    if let Some(status) = details
        .proxy_status
        .as_ref()
        .filter(|s| truthy(s))
        .and_then(Value::as_object)
    {
        match status.get("final_route").and_then(Value::as_str) {
            Some("proxy") => summary.push_str(" - fetched via proxy"),
            Some("direct") if status.get("configured").is_some_and(truthy) => {
                let mut reason = status
                    .get("fallback_reason")
                    .filter(|r| truthy(r))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                // the page the proxy refused, when it's known
                if let Some(failed) = status
                    .get("fallback_details")
                    .and_then(|d| d.get("failed_url"))
                    .and_then(Value::as_str)
                    .filter(|u| !u.is_empty())
                {
                    reason = format!("{reason}: {}", netloc(failed).unwrap_or(failed));
                }
                summary.push_str(&format!(" - proxy failed ({reason}), fetched direct"));
            }
            _ => {}
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ace3's other two reasons, and the fallback to the logs without a `requests.json` that
    /// records resource types (`_matched_proxy_status_code`, `_proxy_navigation_failure`).
    #[test]
    fn a_proxied_scan_is_retried_as_ace3_s_manager_decides() {
        let settings = PhishkitSettings::default();
        let refused = json!([
            {"type": "response", "requestId": "1", "status_code": 407},
            {"type": "response", "requestId": "2", "status_code": 200},
        ]);
        assert_eq!(
            main_status(Some(&refused), &settings.proxy_status_codes),
            Some(407)
        );
        let loaded = json!([{"type": "response", "status_code": 200}]);
        assert_eq!(
            main_status(Some(&loaded), &settings.proxy_status_codes),
            None
        );
        // no resource types: the logs say it
        let untyped = json!([{"type": "request", "requestId": "1"}]);
        assert_eq!(
            navigation_failure(
                Some(&untyped),
                "net::ERR_PROXY_AUTH_FAILED",
                "",
                &settings.proxy_error_patterns
            ),
            Some(json!({"matched_error_patterns": ["ERR_PROXY_AUTH_FAILED"]}))
        );
        assert_eq!(
            navigation_failure(None, "fine", "", &settings.proxy_error_patterns),
            None
        );
        assert_eq!(
            navigation_failure(None, "net::ERR_PROXY_AUTH_FAILED", "", &[]),
            None,
            "no patterns, no retry"
        );
        assert_eq!(
            netloc("https://a.example:8443/x?y#z"),
            Some("a.example:8443")
        );
        assert_eq!(netloc("not a url"), None);
    }

    #[test]
    fn names_take_their_types_extension() {
        assert_eq!(splitext("a.b.html"), ("a.b", ".html"));
        assert_eq!(splitext(".bashrc"), (".bashrc", ""));
        assert_eq!(splitext("noext"), ("noext", ""));
        assert_eq!(corrected_name("page", Some("text/html")), "page.html");
        assert_eq!(corrected_name("page.HTML", Some("text/html")), "page.HTML");
        assert_eq!(corrected_name("body.html", Some("text/plain")), "body.html");
        assert_eq!(corrected_name("body", Some("text/plain")), "body.txt");
        assert_eq!(
            corrected_name("doc.bin", Some("application/pdf")),
            "doc.pdf"
        );
        assert_eq!(
            corrected_name("x.dat", Some("application/x-nothing")),
            "x.dat"
        );
        assert_eq!(corrected_name("x.dat", None), "x.dat");
    }

    #[test]
    fn bodies_split_as_ace3s_pattern_splits_them() {
        let corpus =
            "a\n\nMARKER URL: https://x.example/\n\nb\n\nMARKER URL: \n\nc\n\nMARKER URL: y\n\n";
        assert_eq!(split_bodies(corpus), ["a", "b\n\nMARKER URL: \n\nc", ""]);
        assert_eq!(split_bodies("plain"), ["plain"]);
    }

    #[test]
    fn the_summary_is_ace3s() {
        let mut details = PhishkitAnalysis {
            job_id: Some("j".to_owned()),
            scan_type: Some("url".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            summary(&details, None),
            "Phishkit Analysis: scan timed out — no content captured"
        );
        details.output_files = vec!["phishkit/j/dom.html".to_owned()];
        details.exit_code = Some(143);
        details.metrics = Some(json!({"total_bytes_downloaded": 1048576}));
        assert_eq!(
            summary(&details, None),
            "Phishkit Analysis: output files created (phishkit/j/dom.html) - PARTIAL (scanner timed out) - 1.00 MB downloaded"
        );
        assert_eq!(summary(&details, Some("x")), "Phishkit Analysis: failed: x");
    }
}
