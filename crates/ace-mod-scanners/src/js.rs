//! ace3's `JavaScriptDeobfuscationAnalyzer` (`saq/modules/file_analysis/js.py`), with its client
//! (`saq/js_deobfuscator.py`) and what its manager adds to the output
//! (`js_deobfuscator/js_deobfuscator.py`): it runs a script in js-deobfuscator's harness, node:vm
//! with webcrack in a container with no network, and adds the trace the harness reconstructs, and any
//! Blob the script made, for URL extraction.
//!
//! The first run finds the DOM snapshot of the document the script runs in and asks for a scan of
//! the script, with the snapshot as `<script>.dom.json` beside it, as ace3's client copies both to
//! the shared volume. The task waits for the scan as a delayed task; ace3 waits up to
//! `celery_timeout` in its analysis worker. The next run reads the output: the harness's report on
//! stdout, what it wrote to stderr, the exit code, and `deobfuscated.js` and the Blobs in the output
//! directory.
//!
//! What differs from ace3:
//! - The trace's second line is `// source: <path>`, the input's path in the scanner, which in both
//!   is `/js-deobfuscator/input/<job id>/<name>`. ace3's job id is a random UUID, so the trace's bytes
//!   differ on each of its runs; ace4's is made from the module and the script (`crate::job_id`).
//! - ace3 skips writing a file when one is already at its path on disk; here, when the tree has a
//!   file at that path.
//! - ace3's manager reads the container's output as UTF-8 and fails on bytes that aren't; here they
//!   read as U+FFFD.
//! - ace3 adds its files as volatile observables, which ace4 doesn't have.

use std::time::Duration;

use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::html::DomSnapshot;
use ace_results::types::scanners::JavaScriptDeobfuscationAnalysis;
use ace_results::{
    AnalysisType, ObservableKind, Relationship, RelationshipKind, ResultEnvelope, YaraMeta,
};
use ace_sdk::scanners::{JS_DEOBFUSCATOR, ScanInput, ScanRequest, ScanState};
use ace_sdk::takes::{Case, Condition, Takes, Text};
use ace_sdk::tree::TreeView;
use ace_sdk::{Delay, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ScanOutput, dirname, join, read_output, text};

/// ace3's `DEOBFUSCATED_PREFIX`.
pub const DEOBFUSCATED_PREFIX: &str = "deobfuscated-";
const JAVASCRIPT: &str = "script.javascript";
const EXTRACT_URLS: &str = "extract_urls";
/// The modules whose results hold the DOM snapshots (7.5 batch 4).
const SNAPSHOT_MODULES: &[&str] = &["html_js_extraction", "har_extraction"];
/// Celery's error when `result.get(timeout=...)` runs out.
const CELERY_TIMEOUT: &str = "The operation timed out.";

/// ace3's `analysis_module_javascript_deobfuscation` settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct JsSettings {
    /// How long the scanner may run, in seconds.
    pub scanner_timeout: u32,
    /// How long the task waits for the scan, in seconds: ace3's wait on its Celery manager.
    pub celery_timeout: u32,
}

impl Default for JsSettings {
    /// ace3's `etc/saq.default.yaml`.
    fn default() -> Self {
        JsSettings {
            scanner_timeout: 30,
            celery_timeout: 60,
        }
    }
}

/// What the first run leaves for the next.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Waiting {
    job: String,
    dom_snapshot_source: Option<String>,
}

/// The javascript_deobfuscation module.
pub struct JavaScriptDeobfuscationAnalyzer;

impl Module for JavaScriptDeobfuscationAnalyzer {
    const NAME: &'static str = JavaScriptDeobfuscationAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const SCANNERS: &'static [&'static str] = &[JS_DEOBFUSCATOR.name];
    /// Not ace3's: see `tagged_before_file_type`.
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    const READS_TREE: bool = true;
    const READS_TREE_DETAILS: &'static [&'static str] = SNAPSHOT_MODULES;
    /// Each run only reads and writes files; the scanner runs while the task waits.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        memory_mb: 1024,
        cpu_seconds: 60,
    };
    type Output = JavaScriptDeobfuscationAnalysis;
    type Settings = JsSettings;

    fn init(_: &JsSettings) -> Result<Self, ModuleError> {
        Ok(JavaScriptDeobfuscationAnalyzer)
    }

    fn takes(_: &JsSettings) -> Takes {
        // a file with neither file_type's nor another module's tag, and no .js name; whether the
        // tag is file_type's own reads the bytes, which `analyze` does
        Takes::everything().and(
            Condition::Any(vec![
                Condition::yara_meta("type", JAVASCRIPT),
                Condition::Name(Text::ends_with(".js", Case::Exact)),
            ]),
            "not JavaScript",
        )
    }
}

impl Parser for JavaScriptDeobfuscationAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<JsSettings>,
    ) -> Result<Outcome<JavaScriptDeobfuscationAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let has_js_tag = tagged_before_file_type(ctx)?;
        let name = file.name();
        // `takes` declined a file with no tag and no .js name; this is a tag file_type gave
        if !has_js_tag && !name.ends_with(".js") {
            return Ok(Outcome::Skipped("not JavaScript".to_owned()));
        }
        if name.starts_with(DEOBFUSCATED_PREFIX) {
            return Ok(Outcome::Skipped("the module's own output".to_owned()));
        }
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        match (ctx.scan(), ctx.delay_state::<Waiting>()?) {
            (Some(_), Some(waiting)) => finish(ctx, has_js_tag, &waiting),
            _ => start(ctx),
        }
    }
}

/// Whether the script carries `type=script.javascript` from a module other than file_type.
///
/// ace3 runs its modules on a file in its configuration's order, in which `javascript_deobfuscation`
/// comes before `file_type`, so the tag it reads is the one the file came with, from the module that
/// wrote it, and never file_type's. ace4 runs them at once, so which lands first would be a race:
/// the module waits for file_type and leaves out a tag file_type's own test gives. A file both tag
/// is treated as file_type's; such a file is a script whose name ends in `.js`, which runs anyway.
fn tagged_before_file_type(ctx: &TaskContext<JsSettings>) -> Result<bool, ModuleError> {
    let file = ctx.input_file()?;
    let tagged = file
        .yara_meta
        .iter()
        .any(|m| m.name() == "type" && m.value() == JAVASCRIPT);
    if !tagged {
        return Ok(false);
    }
    let Some(file_type) = ctx.dependency_result::<FileTypeAnalysis>()? else {
        return Ok(true);
    };
    let data = std::fs::read(&file.local_path)?;
    Ok(!ace_mod_files::file_type::tags_javascript(
        file.path.as_str(),
        &file_type.mime,
        &data,
    ))
}

/// The first run: the scan, and what the next run needs.
fn start(
    ctx: &TaskContext<JsSettings>,
) -> Result<Outcome<JavaScriptDeobfuscationAnalysis>, ModuleError> {
    let file = ctx.input_file()?;
    let settings = ctx.settings();
    let job = crate::job_id(ctx, JavaScriptDeobfuscationAnalysis::MODULE);
    let (snapshot, source) = match ctx.tree() {
        Some(tree) => find_dom_snapshot(tree, file.path.as_str()),
        None => (None, None),
    };
    let input = format!("{job}/{}", file.name());
    let mut request = ScanRequest::new(
        JS_DEOBFUSCATOR.name,
        Duration::from_secs(u64::from(settings.scanner_timeout)),
    )
    .arg(format!("{}/{input}", JS_DEOBFUSCATOR.input_dir))
    .arg(format!("{}/deobfuscated.js", JS_DEOBFUSCATOR.output_dir))
    .input(ScanInput {
        name: input.clone(),
        sha256: file.sha256,
        size: file.size,
    });
    if let Some(snapshot) = snapshot {
        let bytes = serde_json::to_vec(&snapshot).map_err(ModuleError::other)?;
        request = request.input(ctx.write_scan_input(&format!("{input}.dom.json"), &bytes)?);
    }
    let wait = Duration::from_secs(u64::from(settings.celery_timeout));
    let delay = Delay::new(wait, wait + Duration::from_secs(1))
        .with_state(&Waiting {
            job,
            dom_snapshot_source: source,
        })?
        .with_scan(request);
    Ok(Outcome::Delay(delay))
}

/// `_find_dom_snapshot`: the snapshot whose files include the script, or, for a script fetched from
/// a URL, the one of the document that URL was `extracted_from`, with that document's path.
fn find_dom_snapshot(tree: &TreeView, path: &str) -> (Option<DomSnapshot>, Option<String>) {
    let snapshot_of = |path: &str| -> Option<DomSnapshot> {
        tree.results
            .iter()
            .filter(|r| SNAPSHOT_MODULES.contains(&r.module.as_str()))
            .filter_map(|r| r.details.as_ref()?.get("dom_snapshots")?.as_array())
            .flatten()
            .filter(|s| {
                s["files"]
                    .as_array()
                    .is_some_and(|files| files.iter().any(|f| f.as_str() == Some(path)))
            })
            .filter_map(|s| serde_json::from_value(s["snapshot"].clone()).ok())
            // the last one written is the file's sidecar
            .next_back()
    };
    if let Some(own) = snapshot_of(path) {
        return (Some(own), None);
    }
    // the analyses that added the script, each on a URL a document's script referenced
    let this = tree.this;
    for result in tree
        .results
        .iter()
        .filter(|r| r.added.iter().any(|a| a.observable == this))
    {
        let Some(url) = tree.observables.get(result.observable) else {
            continue;
        };
        if url.kind != ObservableKind::Url {
            continue;
        }
        for relationship in url
            .relationships
            .iter()
            .filter(|r| r.kind == RelationshipKind::ExtractedFrom)
        {
            let Some(document) = tree.observables.get(relationship.target) else {
                continue;
            };
            if document.kind != ObservableKind::File {
                continue;
            }
            for document_path in &document.paths {
                if let Some(snapshot) = snapshot_of(&document_path.path) {
                    return (Some(snapshot), Some(document_path.path.clone()));
                }
            }
        }
    }
    (None, None)
}

/// The next run: what the scan brought back.
fn finish(
    ctx: &TaskContext<JsSettings>,
    has_js_tag: bool,
    waiting: &Waiting,
) -> Result<Outcome<JavaScriptDeobfuscationAnalysis>, ModuleError> {
    let file = ctx.input_file()?;
    let scan = ctx.scan().ok_or_else(|| ModuleError::other("no scan"))?;
    let mut result = ResultEnvelope::new(JavaScriptDeobfuscationAnalysis {
        dom_snapshot_source: waiting.dom_snapshot_source.clone(),
        ..Default::default()
    });
    result.analyzed.add_tag("js");
    // why the scan gave nothing, or stopped part way: the result's error, ace3's `Analysis.error`
    let mut error: Option<String> = None;
    let details = &mut result.details;
    let output = match scan.state {
        ScanState::Completed => match &scan.output {
            Some(archive) => Some(read_output(ctx, archive, &|_| false)?),
            None => None,
        },
        // the manager's answer when the scanner's container ran past its timeout
        ScanState::TimedOut => {
            details.stdout = Some(String::new());
            details.stderr = Some(format!(
                "scanner container timed out after {}s",
                ctx.settings().scanner_timeout
            ));
            details.exit_code = Some(-1);
            details.event_count = 0;
            None
        }
        ScanState::Pending => {
            let error = format!("js deobfuscator call failed: {CELERY_TIMEOUT}");
            return Ok(done(result, Some(error)));
        }
        ScanState::Failed | ScanState::Abandoned | ScanState::Cancelled => {
            let error = format!(
                "js deobfuscator call failed: {}",
                scan.error.as_deref().unwrap_or(scan.state.as_str())
            );
            return Ok(done(result, Some(error)));
        }
    };
    let blob_names = match &output {
        Some(output) => read_report(output, scan.exit_code, details, &mut error)?,
        None => Vec::new(),
    };

    // a parse failure proves it isn't JavaScript; a failure while it ran doesn't
    let source_parsed =
        error.is_none() || details.error_type == Some(Value::String("runtime".to_owned()));
    if details.exit_code == Some(0) && source_parsed && !has_js_tag {
        result.analyzed.add_yara_meta(meta()?);
    }
    let details = &mut result.details;
    if details.exit_code != Some(0) {
        // a scanner that timed out or crashed reports no error of its own
        if error.is_none() {
            error = Some(tool_failure_reason(
                "js deobfuscator",
                details.exit_code,
                details.stderr.as_deref().unwrap_or_default(),
            ));
        }
        return Ok(done(result, error));
    }
    let Some(output) = output else {
        return Ok(done(result, error));
    };
    let Some(trace) = output.at("deobfuscated.js") else {
        return Ok(done(result, error));
    };
    if trace.file.size == 0 || (details.event_count == 0 && error.is_none()) {
        return Ok(done(result, error));
    }
    let dir = dirname(file.path.as_str());
    let tree = ctx.tree();
    let taken = |path: &str| {
        tree.is_some_and(|t| {
            t.observables
                .iter()
                .any(|o| o.paths.iter().any(|p| p.path == path))
        })
    };
    let target = join(dir, &format!("{DEOBFUSCATED_PREFIX}{}", file.name()));
    if taken(&target) {
        return Ok(done(result, error));
    }
    let source = ace_results::ObservableRef::new(ObservableKind::File, file.sha256.to_hex());
    let mut new_file = trace.file.clone();
    new_file.path = ace_results::AlertPath::new(&target).map_err(ModuleError::other)?;
    new_file.relationships.push(Relationship::new(
        RelationshipKind::ExtractedFrom,
        source.clone(),
    ));
    new_file
        .exclude_modules
        .push(JavaScriptDeobfuscationAnalysis::MODULE.to_owned());
    new_file.yara_meta.push(meta()?);
    new_file.directives.push(EXTRACT_URLS.to_owned());
    result.details.extracted_files.push(target);
    result.files.push(new_file);

    for blob in blob_names {
        // `result_by_basename`: the last file of that name in the walk
        let Some(found) = output.files.iter().rev().find(|f| f.name() == blob) else {
            continue;
        };
        let target = join(dir, &format!("{}.{blob}", file.name()));
        if taken(&target) || result.files.iter().any(|f| f.path.as_str() == target) {
            continue;
        }
        let Ok(path) = ace_results::AlertPath::new(&target) else {
            continue;
        };
        let mut new_file = found.file.clone();
        new_file.path = path;
        new_file.relationships.push(Relationship::new(
            RelationshipKind::ExtractedFrom,
            source.clone(),
        ));
        new_file.directives.push(EXTRACT_URLS.to_owned());
        result.details.extracted_files.push(target);
        result.files.push(new_file);
    }
    Ok(done(result, error))
}

/// What the manager and the module read of the scan: stdout, stderr, the exit code, and the report,
/// which the manager parses from stdout. Returns the Blobs the report names.
fn read_report(
    output: &ScanOutput,
    exit_code: Option<i32>,
    details: &mut JavaScriptDeobfuscationAnalysis,
    error: &mut Option<String>,
) -> Result<Vec<String>, ModuleError> {
    let stdout = text(&output.stdout);
    details.stdout = Some(stdout.clone());
    details.stderr = Some(text(&output.stderr));
    details.exit_code = Some(i64::from(exit_code.unwrap_or(-1)));
    // json.loads(stdout or "{}"), or the manager's stand-in
    let source = if stdout.is_empty() { "{}" } else { &stdout };
    let report = crate::json_loads(source)
        .unwrap_or_else(|| serde_json::json!({"status": "parse_error", "raw_stdout": stdout}));
    let Some(report) = report.as_object() else {
        return Err(ModuleError::other(format!(
            "'{}' object has no attribute 'get'",
            py_type(&report)
        )));
    };
    details.event_count = py_int(report.get("event_count"))?;
    details.secondary_script_count = py_int(report.get("secondary_script_count"))?;
    // js.py's `str(report["error"])`
    if let Some(reported) = report.get("error").filter(|e| truthy(e)) {
        *error = Some(py_str(reported));
    }
    details.error_type = report.get("error_type").cloned().filter(|v| !v.is_null());
    details.webcrack_status = report
        .get("webcrack_status")
        .cloned()
        .filter(|v| !v.is_null());
    details.webcrack_error = report
        .get("webcrack_error")
        .cloned()
        .filter(|v| !v.is_null());
    details.dom_snapshot = report.get("dom_snapshot").is_some_and(truthy);
    Ok(report
        .get("blob_files")
        .and_then(Value::as_array)
        .map(|blobs| {
            blobs
                .iter()
                .filter_map(|b| b.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default())
}

/// `int(value or 0)`.
fn py_int(value: Option<&Value>) -> Result<i64, ModuleError> {
    let Some(value) = value.filter(|v| truthy(v)) else {
        return Ok(0);
    };
    match value {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f.trunc() as i64))
            .ok_or_else(|| ModuleError::other(format!("int() of {n}"))),
        Value::String(s) => ace_pycompat::pystr::strip(s)
            .replace('_', "")
            .parse::<i64>()
            .map_err(|_| {
                ModuleError::other(format!("invalid literal for int() with base 10: {s:?}"))
            }),
        other => Err(ModuleError::other(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            py_type(other)
        ))),
    }
}

/// Python's truth of a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// The name of a JSON value's Python type.
pub fn py_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn meta() -> Result<YaraMeta, ModuleError> {
    YaraMeta::new("type", JAVASCRIPT).map_err(ModuleError::other)
}

/// The result, with its error and ace3's `generate_summary`.
fn done(
    mut result: ResultEnvelope<JavaScriptDeobfuscationAnalysis>,
    error: Option<String>,
) -> Outcome<JavaScriptDeobfuscationAnalysis> {
    // a reason that is all whitespace is no reason: ace3's setter raises on one
    let error = error.filter(|e| !e.trim().is_empty());
    result.summary = summary(&result.details, error.as_deref());
    result.error = error;
    Outcome::Done(result)
}

/// ace3's `tool_failure_reason` (`saq/sandbox/runner.py`): how the scanner exited, and the last line
/// it wrote to stderr. The status is unknown when the scan brought none back.
fn tool_failure_reason(tool: &str, returncode: Option<i64>, stderr: &str) -> String {
    let mut reason = match returncode {
        None => format!("{tool} exited with an unknown status"),
        // 128 + N is a command killed by signal N, up to SIGRTMAX
        Some(code) if 128 < code && code <= 128 + 64 => {
            format!("{tool} was killed by signal {}", code - 128)
        }
        Some(code) => format!("{tool} exited with status {code}"),
    };
    if let Some(last) = ace_pycompat::pystr::splitlines(ace_pycompat::pystr::strip(stderr)).last() {
        reason.push_str(": ");
        reason.extend(last.chars().take(500));
    }
    reason
}

/// `generate_summary`, with the result's error.
pub fn summary(details: &JavaScriptDeobfuscationAnalysis, error: Option<&str>) -> Option<String> {
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        return Some(format!("JavaScript Deobfuscation: failed: {error}"));
    }
    if details.exit_code != Some(0) || details.extracted_files.is_empty() {
        return None;
    }
    let mut summary = format!(
        "JavaScript Deobfuscation: extracted {} ({} events, {} secondary scripts)",
        crate::format_item_list_for_summary(&details.extracted_files),
        details.event_count,
        details.secondary_script_count,
    );
    if let Some(Value::String(status)) = &details.webcrack_status
        && status.starts_with("failed")
    {
        summary.push_str(&format!(" (webcrack {status})"));
    }
    Some(summary)
}

/// `str(value)` of a JSON value as Python's json gives it: a string as itself, anything else as
/// its JSON.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ints_and_truth_read_as_python_reads_them() {
        assert_eq!(py_int(None).ok(), Some(0));
        assert_eq!(py_int(Some(&json!(null))).ok(), Some(0));
        assert_eq!(py_int(Some(&json!(7))).ok(), Some(7));
        assert_eq!(py_int(Some(&json!(7.9))).ok(), Some(7));
        assert_eq!(py_int(Some(&json!(" 12 "))).ok(), Some(12));
        assert!(py_int(Some(&json!("x"))).is_err());
        assert!(py_int(Some(&json!([1]))).is_err());
        assert!(!truthy(&json!("")));
        assert!(truthy(&json!({"a": 1})));
    }

    #[test]
    fn the_summary_is_ace3s() {
        let mut details = JavaScriptDeobfuscationAnalysis {
            extracted_files: vec!["deobfuscated-a.js".to_owned()],
            exit_code: Some(0),
            event_count: 3,
            webcrack_status: Some(json!("failed: x")),
            ..Default::default()
        };
        assert_eq!(
            summary(&details, None).as_deref(),
            Some(
                "JavaScript Deobfuscation: extracted deobfuscated-a.js (3 events, 0 secondary scripts) (webcrack failed: x)"
            )
        );
        assert_eq!(
            summary(&details, Some("boom")).as_deref(),
            Some("JavaScript Deobfuscation: failed: boom")
        );
        details.exit_code = Some(1);
        assert_eq!(summary(&details, None), None);
        // a scanner that reports no error of its own: how it exited, and its last line
        assert_eq!(
            tool_failure_reason(
                "js deobfuscator",
                Some(-1),
                "a\nscanner container timed out after 30s\n"
            ),
            "js deobfuscator exited with status -1: scanner container timed out after 30s"
        );
        assert_eq!(
            tool_failure_reason("js deobfuscator", None, ""),
            "js deobfuscator exited with an unknown status"
        );
        assert_eq!(
            tool_failure_reason("js deobfuscator", Some(137), " "),
            "js deobfuscator was killed by signal 9"
        );
    }
}
