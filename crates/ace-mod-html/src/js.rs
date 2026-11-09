//! `html_js_extraction`: ace3's `HTMLJavaScriptExtractor`
//! (`saq/modules/file_analysis/html_js_extraction.py`).
//!
//! For an HTML, SVG or MHTML file, by its extension or by the mime type `file_type` gave it: each
//! inline `<script>` and each inline event handler as a `.js` file beside the document, tagged
//! `type=script.javascript`, with a DOM snapshot of the document for the JavaScript deobfuscator,
//! and each external script's source as a `url` or `uri_path` observable.
//!
//! Where ace4 departs:
//!
//! - The DOM snapshots are in the result's `dom_snapshots`, with the files whose `.dom.json`
//!   sidecar each is, since ace4 keeps no file outside the tree. Past 16 MiB of them in one result,
//!   a document's snapshot isn't kept and its sidecars aren't listed.
//! - ace3's root takes at most 500 files and 500 URLs (`maximum_observable_count`), which ace4's
//!   core doesn't, so this writes at most 500 scripts and adds at most 500 URLs, as ace3 would
//!   when nothing else in the root had any. Where ace3 has no limit, on `uri_path` observables, this
//!   stops at 500 too, so a crafted document can't add hundreds of thousands.
//! - A file name past 255 bytes fails to open in ace3, which skips that script; here too.

use std::collections::HashSet;

use ace_lxml::soup::Tree;
use ace_pycompat::pystr;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::html::{DomSnapshot, HtmlJavaScriptExtractionAnalysis};
use ace_results::{
    AnalysisType, NewFile, NewObservable, ObservableKind, ObservableRef, Relationship,
    RelationshipKind, ResultEnvelope, YaraMeta,
};
use ace_sdk::{InputFile, Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use ace_urlfinder::Url;
use schemars::JsonSchema;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::dom::{self, Kept, Sidecars};
use crate::mhtml;
use crate::py::{NAME_MAX_BYTES, ends_with_lower, splitext_root};
use crate::{
    DIRECTIVE_CRAWL, DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_PREVIEW, MAX_FILES, MAX_URLS,
    copied_directives,
};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<HtmlJavaScriptExtractor>();

const HTML_EXTENSIONS: [&str; 3] = [".html", ".htm", ".svg"];
const MHTML_EXTENSIONS: [&str; 2] = [".mhtml", ".mht"];
const HTML_MIME_TYPES: [&str; 4] = [
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "message/rfc822",
];
const JAVASCRIPT_TYPES: [&str; 5] = [
    "text/javascript",
    "application/javascript",
    "text/ecmascript",
    "application/ecmascript",
    "",
];

/// `EVENT_ATTRIBUTES`, in ace3's order.
const EVENT_ATTRIBUTES: [&str; 29] = [
    "onclick",
    "ondblclick",
    "onmousedown",
    "onmouseup",
    "onmouseover",
    "onmouseout",
    "onmousemove",
    "onkeydown",
    "onkeyup",
    "onkeypress",
    "onload",
    "onunload",
    "onerror",
    "onabort",
    "onchange",
    "onsubmit",
    "onreset",
    "onfocus",
    "onblur",
    "onresize",
    "onscroll",
    "onselect",
    "ondrag",
    "ondrop",
    "ondragstart",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
];

/// ace3's `analysis_module_html_js_extraction` settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct HtmlJsSettings {
    /// The shortest script extracted, in characters.
    pub min_script_size: usize,
    pub extract_event_handlers: bool,
    /// The longest event handler extracted, in characters.
    pub max_event_handler_size: usize,
    /// Skip a script seen before in the same file.
    pub deduplicate: bool,
    /// Snapshot the document for each script.
    pub emit_dom_snapshot: bool,
    /// A snapshot's JSON past this many bytes is cut short.
    pub dom_snapshot_max_bytes: usize,
}

impl Default for HtmlJsSettings {
    fn default() -> Self {
        HtmlJsSettings {
            min_script_size: 10,
            extract_event_handlers: true,
            max_event_handler_size: 8192,
            deduplicate: true,
            emit_dom_snapshot: true,
            dom_snapshot_max_bytes: dom::DOM_SNAPSHOT_MAX_BYTES,
        }
    }
}

pub struct HtmlJavaScriptExtractor;

impl Module for HtmlJavaScriptExtractor {
    const NAME: &'static str = HtmlJavaScriptExtractionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    type Output = HtmlJavaScriptExtractionAnalysis;
    type Settings = HtmlJsSettings;

    fn init(_: &HtmlJsSettings) -> Result<Self, ModuleError> {
        Ok(HtmlJavaScriptExtractor)
    }
}

/// `is_json_document(content)`: the whole file is JSON, as an HTTP archive is.
pub fn is_json_document(content: &[u8]) -> bool {
    let start = content
        .iter()
        .position(|b| !b" \t\n\r\x0b\x0c".contains(b))
        .unwrap_or(content.len());
    if !matches!(content.get(start), Some(b'{' | b'[')) {
        return false;
    }
    ace_pycompat::json::loads_bytes(content).is_ok()
}

fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a document's extraction stopped: what Python raises, which ace3 logs and goes on past,
/// or a failure of the task itself.
enum Failure {
    Python(String),
    Task(ModuleError),
}

impl From<ModuleError> for Failure {
    fn from(error: ModuleError) -> Self {
        Failure::Task(error)
    }
}

impl From<ace_sdk::FileOutputError> for Failure {
    fn from(error: ace_sdk::FileOutputError) -> Self {
        Failure::Task(error.into())
    }
}

/// Which list a saved script goes in.
#[derive(Clone, Copy)]
enum Tracking {
    Inline,
    Handler,
}

/// The document being read: its snapshot, kept for the result at its first sidecar.
struct Document {
    snapshot: DomSnapshot,
    kept: Option<Kept>,
}

/// One run's state: what `execute_analysis` builds up.
struct Run<'a> {
    ctx: &'a TaskContext<HtmlJsSettings>,
    file: &'a InputFile,
    analysis: HtmlJavaScriptExtractionAnalysis,
    files: Vec<NewFile>,
    observables: Vec<NewObservable>,
    seen_hashes: HashSet<String>,
    sidecars: Sidecars,
    document: Option<Document>,
    urls: usize,
    uri_paths: usize,
}

impl Run<'_> {
    fn source(&self) -> ObservableRef {
        ObservableRef::new(ObservableKind::File, self.file.sha256.to_hex())
    }

    /// The URL the document was loaded from: its `downloaded_from` URL.
    fn page_url(&self) -> Option<&str> {
        self.ctx
            .observable()
            .relationship(RelationshipKind::DownloadedFrom)
            .filter(|r| r.target.kind == ObservableKind::Url)
            .map(|r| r.target.value.as_str())
    }

    /// `_extract_javascript_from_html`.
    fn extract(&mut self, html: &[u8]) -> Result<(), Failure> {
        let text = pystr::decode_utf8_ignore(html);
        let Some(tree) = dom::parse_document(&text) else {
            return Ok(());
        };
        let settings = self.ctx.settings();
        self.document = if settings.emit_dom_snapshot {
            dom::build_dom_snapshot(&tree, settings.dom_snapshot_max_bytes, self.page_url()).map(
                |snapshot| Document {
                    snapshot,
                    kept: None,
                },
            )
        } else {
            None
        };
        self.inline_scripts(&tree)?;
        self.external_scripts(&tree)?;
        if settings.extract_event_handlers {
            self.event_handlers(&tree)?;
        }
        Ok(())
    }

    /// Whether `content` was seen before, counting it as a duplicate if so.
    fn duplicate(&mut self, content: &str) -> bool {
        if !self.ctx.settings().deduplicate {
            return false;
        }
        if !self.seen_hashes.insert(sha256_hex(content)) {
            self.analysis.duplicate_count += 1;
            return true;
        }
        false
    }

    fn inline_scripts(&mut self, tree: &Tree) -> Result<(), Failure> {
        let min = self.ctx.settings().min_script_size;
        for script in tree.elements_named("script") {
            self.ctx.check_cancelled()?;
            if dom::get_script_source(tree, script).is_some() {
                continue;
            }
            let script_type = match tree.get(script, "type") {
                Some(value) => pystr::lower(&value.joined()).into_owned(),
                None => "text/javascript".to_owned(),
            };
            if !JAVASCRIPT_TYPES.contains(&script_type.as_str()) {
                continue;
            }
            let Some(content) = tree.string(script).filter(|s| !s.is_empty()) else {
                continue;
            };
            let mut content = pystr::strip(content);
            if let Some(inner) = content
                .strip_prefix("<![CDATA[")
                .and_then(|rest| rest.strip_suffix("]]>"))
            {
                content = pystr::strip(inner);
            }
            if content.chars().count() < min {
                continue;
            }
            self.analysis.script_count += 1;
            if self.duplicate(content) {
                continue;
            }
            self.save(content, "inline", Tracking::Inline)?;
        }
        Ok(())
    }

    fn external_scripts(&mut self, tree: &Tree) -> Result<(), Failure> {
        let mut extracted_url = false;
        for script in tree.elements_named("script") {
            self.ctx.check_cancelled()?;
            let Some(source) = dom::get_script_source(tree, script) else {
                continue;
            };
            let source = pystr::strip(&source);
            if source.is_empty() {
                continue;
            }
            self.analysis.script_count += 1;
            let is_url = Url::new(source)
                .is_url()
                .map_err(|e| Failure::Python(e.to_string()))?;
            let kind = if is_url {
                ObservableKind::Url
            } else {
                ObservableKind::UriPath
            };
            // ace3's root stops taking URLs at 500; this stops uri_paths there too
            let added = if is_url {
                &mut self.urls
            } else {
                &mut self.uri_paths
            };
            let known = self
                .observables
                .iter()
                .any(|o| o.kind == kind && o.value == source);
            if !known {
                if *added >= MAX_URLS {
                    continue;
                }
                *added += 1;
                let mut observable = NewObservable::new(kind, source);
                if is_url
                    && self
                        .ctx
                        .observable()
                        .has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
                {
                    observable.directives.push(DIRECTIVE_CRAWL.to_owned());
                }
                observable.relationships.push(Relationship::new(
                    RelationshipKind::ExtractedFrom,
                    self.source(),
                ));
                self.observables.push(observable);
            } else if is_url
                && self
                    .ctx
                    .observable()
                    .has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS)
                && let Some(observable) = self
                    .observables
                    .iter_mut()
                    .find(|o| o.kind == kind && o.value == source)
                && !observable.directives.iter().any(|d| d == DIRECTIVE_CRAWL)
            {
                observable.directives.push(DIRECTIVE_CRAWL.to_owned());
            }
            if is_url {
                self.analysis.extracted_urls.push(source.to_owned());
                extracted_url = true;
            } else {
                self.analysis.extracted_uri_paths.push(source.to_owned());
            }
        }
        if extracted_url {
            let path = self.file.path.to_string();
            let sidecar = format!("{}.dom.json", self.file.name());
            self.write_sidecar(&path, &sidecar);
        }
        Ok(())
    }

    fn event_handlers(&mut self, tree: &Tree) -> Result<(), Failure> {
        let settings = self.ctx.settings();
        let (min, max) = (settings.min_script_size, settings.max_event_handler_size);
        for tag in tree.elements() {
            self.ctx.check_cancelled()?;
            for attr in EVENT_ATTRIBUTES {
                let Some(value) = tree.get(tag, attr) else {
                    continue;
                };
                let value = value.joined();
                let handler = pystr::strip(&value);
                let len = handler.chars().count();
                if handler.is_empty() || len < min || len > max {
                    continue;
                }
                self.analysis.script_count += 1;
                if self.duplicate(handler) {
                    continue;
                }
                self.save(handler, &format!("event_{attr}"), Tracking::Handler)?;
            }
        }
        Ok(())
    }

    /// `_write_dom_snapshot`: the document's snapshot as the sidecar of `path`, listed by its
    /// name once. Nothing when the document has no snapshot.
    fn write_sidecar(&mut self, path: &str, sidecar: &str) {
        let Some(document) = self.document.as_mut() else {
            return;
        };
        let kept = *document
            .kept
            .get_or_insert_with(|| self.sidecars.keep(document.snapshot.clone()));
        if self.sidecars.write(path, kept)
            && !self
                .analysis
                .dom_snapshot_files
                .iter()
                .any(|f| f == sidecar)
        {
            self.analysis.dom_snapshot_files.push(sidecar.to_owned());
        }
    }

    /// `_save_and_register_script`.
    fn save(
        &mut self,
        content: &str,
        script_type: &str,
        tracking: Tracking,
    ) -> Result<(), Failure> {
        let hash = sha256_hex(content);
        let index = match tracking {
            Tracking::Inline => self.analysis.extracted_files.len(),
            Tracking::Handler => self.analysis.inline_handlers.len(),
        };
        let base = splitext_root(self.file.name());
        let name = format!("{base}_js_{script_type}_{index}_{}.js", &hash[..8]);
        // open() fails on a name the file system can't hold, which ace3 logs
        if name.len() > NAME_MAX_BYTES {
            return Ok(());
        }
        // ace3's root takes no more files
        if self.files.len() >= MAX_FILES {
            return Ok(());
        }
        let path = match self.file.path.as_str().rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/{name}"),
            None => name.clone(),
        };
        let meta = YaraMeta::new("type", "script.javascript")
            .map_err(|e| Failure::Task(ModuleError::other(e)))?;
        let mut new_file = self.ctx.write_file(&path, content.as_bytes(), &[meta])?;
        new_file.relationships.push(Relationship::new(
            RelationshipKind::ExtractedFrom,
            self.source(),
        ));
        new_file
            .exclude_modules
            .push(HtmlJavaScriptExtractor::NAME.to_owned());
        let (directives, yara_meta) = copied_directives(self.ctx.observable(), self.file);
        for directive in directives {
            new_file.add_directive(directive);
        }
        for meta in yara_meta {
            if !new_file.yara_meta.contains(&meta) {
                new_file.yara_meta.push(meta);
            }
        }
        new_file.directives.retain(|d| d != DIRECTIVE_PREVIEW);
        let file_path = new_file.path.to_string();
        self.files.push(new_file);
        match tracking {
            Tracking::Inline => self.analysis.extracted_files.push(file_path.clone()),
            Tracking::Handler => self.analysis.inline_handlers.push(file_path.clone()),
        }
        self.write_sidecar(&file_path, &format!("{name}.dom.json"));
        Ok(())
    }

    fn summary(&self) -> Option<String> {
        let a = &self.analysis;
        if a.script_count == 0 {
            return None;
        }
        let mut parts = Vec::new();
        if !a.extracted_files.is_empty() {
            parts.push(format!("{} inline script(s)", a.extracted_files.len()));
        }
        if !a.extracted_urls.is_empty() {
            parts.push(format!("{} external URL(s)", a.extracted_urls.len()));
        }
        if !a.extracted_uri_paths.is_empty() {
            parts.push(format!("{} URI path(s)", a.extracted_uri_paths.len()));
        }
        if !a.inline_handlers.is_empty() {
            parts.push(format!("{} event handler(s)", a.inline_handlers.len()));
        }
        let mut summary = format!("HTML JavaScript Extraction: {}", parts.join(", "));
        if a.duplicate_count > 0 {
            summary.push_str(&format!(" ({} duplicate(s) skipped)", a.duplicate_count));
        }
        Some(summary)
    }
}

impl Parser for HtmlJavaScriptExtractor {
    fn analyze(
        &self,
        ctx: &TaskContext<HtmlJsSettings>,
    ) -> Result<Outcome<HtmlJavaScriptExtractionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let name = file.name();
        let is_html = HTML_EXTENSIONS
            .iter()
            .chain(MHTML_EXTENSIONS.iter())
            .any(|ext| ends_with_lower(name, ext));
        let mime = ctx
            .dependency_result::<FileTypeAnalysis>()?
            .map(|file_type| file_type.mime);
        let content = std::fs::read(&file.local_path)?;
        if !is_html {
            if file
                .yara_meta
                .iter()
                .any(|m| m.name() == "type" && m.value() == "script.javascript")
            {
                return Ok(Outcome::Skipped(
                    "JavaScript source sniffed as HTML".to_owned(),
                ));
            }
            if !mime
                .as_deref()
                .is_some_and(|m| HTML_MIME_TYPES.contains(&m))
            {
                return Ok(Outcome::Skipped("not HTML".to_owned()));
            }
            if is_json_document(&content) {
                return Ok(Outcome::Skipped("a JSON file sniffed as HTML".to_owned()));
            }
        }
        let is_mhtml = MHTML_EXTENSIONS
            .iter()
            .any(|ext| ends_with_lower(name, ext))
            || mime.as_deref() == Some("message/rfc822");
        let documents = if is_mhtml {
            mhtml::html_parts(&content)
        } else {
            vec![content]
        };

        let mut run = Run {
            ctx,
            file,
            analysis: HtmlJavaScriptExtractionAnalysis::default(),
            files: Vec::new(),
            observables: Vec::new(),
            seen_hashes: HashSet::new(),
            sidecars: Sidecars::default(),
            document: None,
            urls: 0,
            uri_paths: 0,
        };
        for document in &documents {
            if document.is_empty() {
                continue;
            }
            match run.extract(document) {
                Ok(()) => {}
                // what Python raises is logged and the next document goes on
                Err(Failure::Python(message)) => {
                    tracing::warn!("failed to extract JavaScript from {name}: {message}");
                }
                Err(Failure::Task(error)) => return Err(error),
            }
        }
        let summary = run.summary();
        let Run {
            mut analysis,
            files,
            observables,
            sidecars,
            ..
        } = run;
        analysis.dom_snapshots = sidecars.into_files();
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        result.files = files;
        result.observables = observables;
        Ok(Outcome::Done(result))
    }
}
