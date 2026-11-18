//! `har_extraction`: ace3's `HARExtractor` (`saq/modules/file_analysis/har.py`).
//!
//! An HTTP archive, found by its content (`{"log":` at its start): the HTML and SVG pages and the
//! scripts its responses hold, one file per distinct body, pages first, at most
//! `max_extracted_files`, each written to `<file>.extracted/<NNN>_<name><ext>`, `extracted_from`
//! the archive and `downloaded_from` its URL when that's http or https. A script a page loads with
//! `<script src>` gets that page's DOM snapshot as its sidecar.
//!
//! Where ace4 departs:
//!
//! - The DOM snapshots are in the result's `dom_snapshots`, since ace4 keeps no file outside the
//!   tree.
//! - What Python raises out of ace3's module, such as `urlsplit`'s `ValueError` on a URL with a
//!   broken IPv6 host, leaves ace3's analysis as far as it got; ace4 stores that much.
//! - A `status` the archive writes as a number past 64 bits is its nearest float, and NaN or an
//!   infinity is null, since JSON here has no such numbers.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use ace_lxml::soup::Tree;
use ace_pycompat::json::{JsonStr, Value};
use ace_pycompat::parse::{unquote, urljoin, urlsplit};
use ace_pycompat::pystr;
use ace_results::types::html::{DomSnapshot, HarAnalysis, HarResponse};
use ace_results::{
    AnalysisType, NewFile, NewObservable, ObservableKind, ObservableRef, Relationship,
    RelationshipKind, ResultEnvelope,
};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use regex::bytes::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::dom::{self, Kept, Sidecars};
use crate::py::{encode_replace, py_str, truncate_chars};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<HarExtractor>();

/// `RE_HAR_HEADER`.
static RE_HAR_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?-u)^\s*\{\s*"log"\s*:"#).expect("the pattern compiles"));
const HAR_HEADER_PEEK_BYTES: u64 = 4096;
const MAX_FILE_NAME_LENGTH: usize = 100;

/// `DOCUMENT_EXTENSIONS` and `SCRIPT_EXTENSIONS`.
fn extension(mime_type: &str) -> Option<&'static str> {
    Some(match mime_type {
        "text/html" | "application/xhtml+xml" => ".html",
        "image/svg+xml" => ".svg",
        "application/javascript"
        | "application/x-javascript"
        | "application/ecmascript"
        | "text/javascript"
        | "text/ecmascript" => ".js",
        _ => return None,
    })
}

fn is_document(mime_type: &str) -> bool {
    matches!(
        mime_type,
        "text/html" | "application/xhtml+xml" | "image/svg+xml"
    )
}

/// ace3's `analysis_module_har_extraction` settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct HarSettings {
    /// The largest archive parsed, in bytes: the whole file is loaded as JSON.
    pub max_file_size: u64,
    /// The most response bodies extracted from one archive, pages first.
    pub max_extracted_files: usize,
}

impl Default for HarSettings {
    fn default() -> Self {
        HarSettings {
            max_file_size: 52_428_800,
            max_extracted_files: 50,
        }
    }
}

pub struct HarExtractor;

impl Module for HarExtractor {
    const NAME: &'static str = HarAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = HarAnalysis;
    type Settings = HarSettings;

    fn init(_: &HarSettings) -> Result<Self, ModuleError> {
        Ok(HarExtractor)
    }

    fn takes(_: &HarSettings) -> Takes {
        Takes::everything().and(Condition::not_empty(), "an empty file")
    }
}

/// `_as_dict(value)`: the value's members when it's an object.
fn members(value: Option<&Value>) -> &[(JsonStr, Value)] {
    match value {
        Some(Value::Object(members)) => members,
        _ => &[],
    }
}

fn get<'v>(members: &'v [(JsonStr, Value)], key: &str) -> Option<&'v Value> {
    members.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// `get_har_entries(har)`.
fn entries(har: &Value) -> Option<&[Value]> {
    let log = get(members(Some(har)), "log");
    match get(members(log), "entries") {
        Some(Value::Array(entries)) => Some(entries),
        _ => None,
    }
}

/// Python's truth of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(digits) => !digits
            .trim_start_matches('-')
            .trim_start_matches('0')
            .is_empty(),
        Value::Float(f) => *f != 0.0,
        Value::Str(s) => s.py_len() > 0,
        Value::Array(items) => !items.is_empty(),
        Value::Object(members) => !members.is_empty(),
    }
}

/// A value of the archive in a result's details.
fn to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(digits) => {
            if let Ok(n) = digits.parse::<i64>() {
                n.into()
            } else if let Ok(n) = digits.parse::<u64>() {
                n.into()
            } else {
                digits
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number)
            }
        }
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Value::Str(s) => serde_json::Value::String(lossy(s)),
        Value::Array(items) => serde_json::Value::Array(items.iter().map(to_json).collect()),
        Value::Object(members) => serde_json::Value::Object(
            members
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), to_json(v)))
                .collect(),
        ),
    }
}

/// A str from JSON as text, each lone surrogate U+FFFD.
fn lossy(s: &JsonStr) -> String {
    if !s.has_surrogates() {
        return s.as_str().to_owned();
    }
    s.code_points()
        .into_iter()
        .map(|cp| char::from_u32(cp).unwrap_or('\u{fffd}'))
        .collect()
}

/// `isinstance(size, int) and size > length`, a bool being an int.
fn larger_than(size: Option<&Value>, length: usize) -> bool {
    match size {
        Some(Value::Bool(b)) => usize::from(*b) > length,
        Some(Value::Int(digits)) => {
            if digits.starts_with('-') {
                return false;
            }
            match digits.parse::<u128>() {
                Ok(n) => n > length as u128,
                Err(_) => true,
            }
        }
        _ => false,
    }
}

/// `HARResponse`: one body worth a file.
struct Response {
    index: usize,
    url: String,
    mime_type: String,
    status: serde_json::Value,
    body: Vec<u8>,
    truncated: bool,
}

impl Response {
    fn is_document(&self) -> bool {
        is_document(&self.mime_type)
    }

    fn extension(&self) -> &'static str {
        extension(&self.mime_type).unwrap_or(".js")
    }

    /// `file_name`: `<entry index>_<last path segment><extension>`. `urlsplit` raises on some
    /// URLs, as Python's does.
    fn file_name(&self) -> Result<String, ace_pycompat::PyErr> {
        let parts = urlsplit(&self.url, "", true)?;
        let path = parts.path.trim_end_matches('/');
        let last = path.rsplit('/').next().unwrap_or("");
        let mut name = unquote(last).into_owned();
        if name.is_empty() {
            name = parts.hostname().unwrap_or_default();
        }
        if name.is_empty() {
            name = "response".to_owned();
        }
        let sanitized: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let cut = truncate_chars(&sanitized, MAX_FILE_NAME_LENGTH).unwrap_or(&sanitized);
        let mut name = cut.trim_matches(['.', '_']).to_owned();
        if name.is_empty() {
            name = "response".to_owned();
        }
        if !name.to_ascii_lowercase().ends_with(self.extension()) {
            name.push_str(self.extension());
        }
        Ok(format!("{:03}_{name}", self.index))
    }
}

/// `get_har_responses(har)`: the page and script responses, in request order, one per body.
fn responses(entries: &[Value]) -> Vec<Response> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let entry = members(Some(entry));
        let request = members(get(entry, "request"));
        let response = members(get(entry, "response"));
        let content = members(get(response, "content"));
        let Some(Value::Str(url)) = get(request, "url") else {
            continue;
        };
        // lone surrogates can't be text here: each is U+FFFD, which no check below matches
        let url = lossy(url);
        if pystr::lower(&url).starts_with("data:") {
            continue;
        }
        let mime = match get(content, "mimeType") {
            Some(value) if truthy(value) => py_str(value),
            _ => String::new(),
        };
        let mime_type =
            pystr::lower(pystr::strip(mime.split(';').next().unwrap_or(""))).into_owned();
        if extension(&mime_type).is_none() {
            continue;
        }
        let Some(Value::Str(text)) = get(content, "text") else {
            continue;
        };
        if text.py_len() == 0 {
            continue;
        }
        let body = if matches!(get(content, "encoding"), Some(Value::Str(e)) if e == "base64") {
            if text.has_surrogates() {
                continue;
            }
            match ace_pycompat::base64::b64decode(text.as_str()) {
                Ok(body) => body,
                Err(_) => continue,
            }
        } else {
            encode_replace(text)
        };
        if !seen.insert(Sha256::digest(&body)) {
            continue;
        }
        let truncated = larger_than(get(content, "size"), body.len());
        result.push(Response {
            index,
            url,
            mime_type,
            status: get(response, "status").map_or(serde_json::Value::Null, to_json),
            body,
            truncated,
        });
    }
    result
}

/// A page whose snapshot the scripts it loads get.
struct Page {
    snapshot: DomSnapshot,
    kept: Option<Kept>,
    file_path: String,
}

struct Run<'a> {
    ctx: &'a TaskContext<HarSettings>,
    source: ObservableRef,
    extracted_dir: String,
    analysis: HarAnalysis,
    files: Vec<NewFile>,
    observables: Vec<NewObservable>,
    sidecars: Sidecars,
    pages: Vec<Page>,
    /// script URL -> the page that loads it
    page_of: HashMap<String, usize>,
}

impl Run<'_> {
    /// One selected response. An `Err` is what Python raises, which ends ace3's module.
    fn extract(
        &mut self,
        response: Response,
    ) -> Result<Result<(), ace_pycompat::PyErr>, ModuleError> {
        self.ctx.check_cancelled()?;
        let name = match response.file_name() {
            Ok(name) => name,
            Err(error) => return Ok(Err(error)),
        };
        let path = format!("{}/{name}", self.extracted_dir);
        let mut new_file = self.ctx.write_file(&path, &response.body, &[])?;
        new_file.relationships.push(Relationship::new(
            RelationshipKind::ExtractedFrom,
            self.source.clone(),
        ));
        new_file.exclude_modules.push(HarExtractor::NAME.to_owned());
        let scheme = match urlsplit(&response.url, "", true) {
            Ok(parts) => pystr::lower(&parts.scheme).into_owned(),
            Err(error) => {
                self.files.push(new_file);
                return Ok(Err(error));
            }
        };
        if scheme == "http" || scheme == "https" {
            if !self.observables.iter().any(|o| o.value == response.url) {
                self.observables
                    .push(NewObservable::new(ObservableKind::Url, &response.url));
            }
            new_file.relationships.push(Relationship::new(
                RelationshipKind::DownloadedFrom,
                ObservableRef::new(ObservableKind::Url, &response.url),
            ));
        }
        let file_path = new_file.path.to_string();
        self.files.push(new_file);

        let mut record = HarResponse {
            url: response.url.clone(),
            status: response.status.clone(),
            mime_type: response.mime_type.clone(),
            file_path: file_path.clone(),
            truncated: response.truncated,
            loaded_by: None,
        };
        if response.is_document() {
            if let Err(error) = self.collect_page_snapshot(&response, &file_path) {
                return Ok(Err(error));
            }
        } else if let Some(&page) = self.page_of.get(&response.url) {
            let page = &mut self.pages[page];
            let kept = *page
                .kept
                .get_or_insert_with(|| self.sidecars.keep(page.snapshot.clone()));
            if self.sidecars.write(&file_path, kept) {
                record.loaded_by = Some(page.file_path.clone());
            }
        }
        self.analysis.responses.push(record);
        Ok(Ok(()))
    }

    /// `_collect_page_snapshot`: this page's snapshot under each script URL it loads that no
    /// earlier page does.
    fn collect_page_snapshot(
        &mut self,
        response: &Response,
        file_path: &str,
    ) -> Result<(), ace_pycompat::PyErr> {
        let text = pystr::decode_utf8_ignore(&response.body);
        let Some(tree) = dom::parse_document(&text) else {
            return Ok(());
        };
        let mut page: Option<usize> = None;
        for script in tree.elements_named("script") {
            let Some(source) = dom::get_script_source(&tree, script) else {
                continue;
            };
            let source = pystr::strip(&source);
            if source.is_empty() {
                continue;
            }
            let script_url = urljoin(&response.url, source, true)?;
            if self.page_of.contains_key(&script_url) {
                continue;
            }
            let index = match page {
                Some(index) => index,
                None => {
                    let Some(snapshot) = snapshot_of(&tree, &response.url) else {
                        return Ok(());
                    };
                    self.pages.push(Page {
                        snapshot,
                        kept: None,
                        file_path: file_path.to_owned(),
                    });
                    *page.insert(self.pages.len() - 1)
                }
            };
            self.page_of.insert(script_url, index);
        }
        Ok(())
    }
}

fn snapshot_of(tree: &Tree, url: &str) -> Option<DomSnapshot> {
    dom::build_dom_snapshot(tree, dom::DOM_SNAPSHOT_MAX_BYTES, Some(url))
}

fn summary(analysis: &HarAnalysis, error: Option<&str>) -> String {
    if let Some(error) = error {
        return format!("HTTP Archive: failed: {error}");
    }
    let pages = analysis
        .responses
        .iter()
        .filter(|r| is_document(&r.mime_type))
        .count();
    let scripts = analysis.responses.len() - pages;
    let mut summary = format!(
        "HTTP Archive: extracted {pages} pages and {scripts} scripts from {} requests",
        analysis.entry_count
    );
    if let Some(creator) = &analysis.creator {
        summary.push_str(&format!(" ({creator})"));
    }
    if analysis.skipped_count > 0 {
        summary.push_str(&format!(
            ", {} more over the extraction limit",
            analysis.skipped_count
        ));
    }
    summary
}

impl Parser for HarExtractor {
    fn analyze(&self, ctx: &TaskContext<HarSettings>) -> Result<Outcome<HarAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let mut head = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(
                std::fs::File::open(&file.local_path)?,
                HAR_HEADER_PEEK_BYTES,
            ),
            &mut head,
        )?;
        if !RE_HAR_HEADER.is_match(&head) {
            return Ok(Outcome::Skipped("not an HTTP archive".to_owned()));
        }
        let settings = ctx.settings();
        let mut analysis = HarAnalysis::default();
        // `error` is why nothing was extracted: ace3's `Analysis.error`
        let finish = |analysis: HarAnalysis, error: Option<String>| {
            let summary = summary(&analysis, error.as_deref());
            let mut result = ResultEnvelope::new(analysis).with_summary(summary);
            result.error = error;
            Ok(Outcome::Done(result))
        };
        if file.size > settings.max_file_size {
            let error = format!(
                "{} bytes exceeds max_file_size {}",
                file.size, settings.max_file_size
            );
            return finish(analysis, Some(error));
        }
        let data = std::fs::read(&file.local_path)?;
        ctx.check_cancelled()?;
        let har = match ace_pycompat::json::loads_bytes(&data) {
            Ok(har) => har,
            Err(error) => {
                let error = format!("not valid JSON: {}", error.message);
                return finish(analysis, Some(error));
            }
        };
        drop(data);
        let Some(entries) = entries(&har) else {
            return finish(analysis, Some("no log.entries list".to_owned()));
        };
        let creator = members(
            get(members(Some(&har)), "log").and_then(|log| get(members(Some(log)), "creator")),
        );
        if let Some(name) = get(creator, "name").filter(|n| truthy(n)) {
            let version = match get(creator, "version") {
                Some(version) if truthy(version) => py_str(version),
                _ => String::new(),
            };
            analysis.creator =
                Some(pystr::strip(&format!("{} {version}", py_str(name))).to_owned());
        }
        analysis.entry_count = entries.len() as u64;
        let found = responses(entries);
        let total = found.len();
        let (documents, scripts): (Vec<Response>, Vec<Response>) =
            found.into_iter().partition(Response::is_document);
        let selected: Vec<Response> = documents
            .into_iter()
            .chain(scripts)
            .take(settings.max_extracted_files)
            .collect();
        analysis.skipped_count = (total - selected.len()) as u64;
        // os.makedirs raises out of ace3's module on a name the file system can't hold, and ace3's
        // engine marks the analysis failed with the exception
        if file.name().len() + ".extracted".len() > crate::py::NAME_MAX_BYTES {
            let raised = format!(
                "OSError: [Errno 36] File name too long: '{}.extracted'",
                file.path
            );
            return finish(analysis, Some(raised));
        }

        let mut run = Run {
            ctx,
            source: ObservableRef::new(ObservableKind::File, file.sha256.to_hex()),
            extracted_dir: format!("{}.extracted", file.path),
            analysis,
            files: Vec::new(),
            observables: Vec::new(),
            sidecars: Sidecars::default(),
            pages: Vec::new(),
            page_of: HashMap::new(),
        };
        // Where Python raises out of ace3's module, the engine keeps the analysis as far as it got
        // and marks it failed with the exception, as `<type>: <message>` and its crash report's id.
        // The result here is the same, without the id.
        let mut raised = None;
        for response in selected {
            if let Err(error) = run.extract(response)? {
                tracing::warn!("har_extraction stopped where ace3's module raises: {error}");
                raised = Some(error.as_engine_marks());
                break;
            }
        }
        let Run {
            mut analysis,
            files,
            observables,
            sidecars,
            ..
        } = run;
        analysis.dom_snapshots = sidecars.into_files();
        let summary = summary(&analysis, raised.as_deref());
        let mut result = ResultEnvelope::new(analysis).with_summary(summary);
        result.error = raised;
        result.files = files;
        result.observables = observables;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(url: &str, mime_type: &str) -> Response {
        Response {
            index: 7,
            url: url.to_owned(),
            mime_type: mime_type.to_owned(),
            status: serde_json::Value::Null,
            body: Vec::new(),
            truncated: false,
        }
    }

    #[test]
    fn file_names_are_ace3_s() {
        for (url, mime, name) in [
            ("https://x.example.com/start", "text/html", "007_start.html"),
            (
                "https://x.example.com/",
                "text/html",
                "007_x.example.com.html",
            ),
            (
                "https://x.example.com/login.html?next=/a",
                "text/html",
                "007_login.html",
            ),
            (
                "https://x.example.com/a%2Fb%20c",
                "text/html",
                "007_a_b_c.html",
            ),
            (
                "https://x.example.com/icon",
                "image/svg+xml",
                "007_icon.svg",
            ),
            ("https://x.example.com/k.JS", "text/javascript", "007_k.JS"),
            ("https://x.example.com/._x_.", "text/javascript", "007_x.js"),
            (
                "https://x.example.com/caf\u{e9}",
                "text/javascript",
                "007_caf.js",
            ),
            ("about:blank", "text/html", "007_blank.html"),
            ("https:///", "text/html", "007_response.html"),
        ] {
            assert_eq!(
                response(url, mime).file_name().expect("a name"),
                name,
                "{url}"
            );
        }
        assert!(response("http://[::1/x", "text/html").file_name().is_err());
    }

    #[test]
    fn truth_and_sizes_are_python_s() {
        assert!(!truthy(&Value::Int("0".to_owned())));
        assert!(!truthy(&Value::Int("-0".to_owned())));
        assert!(truthy(&Value::Int("-3".to_owned())));
        assert!(larger_than(Some(&Value::Bool(true)), 0));
        assert!(!larger_than(Some(&Value::Float(9.0)), 0));
        assert!(larger_than(
            Some(&Value::Int(
                "99999999999999999999999999999999999999999".to_owned()
            )),
            5
        ));
        assert!(!larger_than(Some(&Value::Int("-1".to_owned())), 0));
    }

    #[test]
    fn the_header_is_found_by_content() {
        assert!(RE_HAR_HEADER.is_match(b" \n{ \"log\" :{"));
        assert!(!RE_HAR_HEADER.is_match(b"{\"data\": 1}"));
        assert!(!RE_HAR_HEADER.is_match(b"x{\"log\":"));
    }
}
