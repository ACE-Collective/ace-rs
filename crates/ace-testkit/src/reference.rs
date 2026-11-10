//! Comparing a port's output with ace3's reference dumps (PLAN.md 1.24).
//!
//! `tools/ace3/dumps/reference/<module>/` holds what one ace3 module produced for each sample.
//! Both sides are put into one normal form, diffed field by field, and every difference has to
//! be listed and explained in the port's `tests/differences.md`. A listed difference that no
//! longer happens fails too, so the list stays true.
//!
//! The normal form:
//!
//! ```text
//! {
//!   "summary": "...",
//!   "details": {...},                         the analysis details as written
//!   "tags": {"single_file_zip": true},        tags on the result itself
//!   "detections": {"<description>": details},
//!   "analyzed": {"tags": {..}, "directives": {..}, "yara_meta": {..}, "detections": {..}},
//!   "observables": {
//!     "email_from:a@example.com": {...},      by type and value
//!     "file:test.zip.extracted/a.js": {...}   files by their path inside the alert
//!   }
//! }
//! ```
//!
//! Each observable carries `tags`, `directives`, `yara_meta`, `detections`, `relationships`
//! (`"<kind> <type>:<value>"`), `excluded_analysis` (module names), and `time`, `redirection`,
//! `sha256` and `size` when it has them, and `display_type` when a module gave it one. Sets are
//! objects whose keys are the members, so a difference names the member. ace3 keeps `yara_meta`
//! tags among the directives as `yara_meta:name=value`; the normal form keeps them only under
//! `yara_meta`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ace_results::{AnalysisType, Detection, NewFile, NewObservable, ObservableAdditions};
use ace_sdk::Outcome;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};

use crate::HarnessError;

pub use ace_results::differences::{
    Difference, Listed, ListedDifferences, diff, glob, path_matches,
};

/// `tools/ace3/dumps/reference`.
pub fn dumps_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/reference")
}

/// One reference dump.
pub struct Dump {
    /// The dump's path under `dumps_dir()`, without `.json`, such as
    /// `email_analyzer/ace3/email/smtp.email.rfc822`.
    pub name: String,
    pub value: Value,
}

impl Dump {
    pub fn load(name: &str) -> Result<Dump, HarnessError> {
        let path = dumps_dir().join(format!("{name}.json"));
        let text = fs::read_to_string(&path)
            .map_err(|e| HarnessError::Fixture(format!("{}: {e}", path.display())))?;
        let value = serde_json::from_str(&text)
            .map_err(|e| HarnessError::Fixture(format!("{}: {e}", path.display())))?;
        Ok(Dump {
            name: name.to_owned(),
            value,
        })
    }

    /// Every dump of one module, by name.
    pub fn all(module: &str) -> Result<Vec<Dump>, HarnessError> {
        let mut names = Vec::new();
        collect(&dumps_dir().join(module), &dumps_dir(), &mut names)?;
        names.sort();
        names.iter().map(|name| Dump::load(name)).collect()
    }

    /// The dump's name inside its module's directory, such as `ace3/email/smtp.email.rfc822`,
    /// which is what `differences.md` rows match.
    pub fn short_name(&self) -> &str {
        self.name
            .split_once('/')
            .map_or(self.name.as_str(), |(_, rest)| rest)
    }

    /// The sample under `samples/` the dump analyzed: its input label for a file.
    pub fn sample(&self) -> Option<&str> {
        let label = self.value["input"]["label"].as_str()?;
        (self.value["input"]["observable"]["type"] == "file").then_some(label)
    }

    /// The analysis of ace3 class `class`, such as `EmailAnalysis`.
    pub fn analysis(&self, class: &str) -> Option<&Value> {
        self.value["analyses"]
            .as_array()?
            .iter()
            .find(|a| a["class"] == class)
    }

    /// The details of ace3's file_type analysis of the input, which a module that depends on
    /// file_type gets as its dependency result.
    pub fn file_type(&self) -> Option<&Value> {
        self.analysis("FileTypeAnalysis").map(|a| &a["details"])
    }

    /// The mime type ace3's file_type module gave the input.
    pub fn mime_type(&self) -> Option<&str> {
        self.analysis("FileTypeAnalysis")?["details"]["mime"].as_str()
    }

    /// The index of the observable of `kind` and `value` in the root the dump kept
    /// (`run_module.py --tree-view`).
    pub fn tree_index(&self, kind: &str, value: &str) -> Option<usize> {
        self.value["tree_view"]["observables"]
            .as_array()?
            .iter()
            .position(|o| o["type"] == kind && o["value"] == value)
    }

    /// The root the dump kept (`run_module.py --tree-view`) as ace4's core would send it to a module
    /// that walks it, with `this` its task's observable: ace3's results without those of the classes
    /// in `leave_out`, such as the module's own, and each result's type its ace4 name where a module
    /// that walks the tree reads it (`ace3_analysis_type`).
    pub fn tree_view(&self, this: usize, leave_out: &[&str]) -> ace_sdk::tree::TreeView {
        use ace_sdk::tree::{TreeAddition, TreeObservable, TreePath, TreeResult, TreeView};
        let view = &self.value["tree_view"];
        let observables = view["observables"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|o| TreeObservable {
                kind: o["type"]
                    .as_str()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or_else(|| {
                        panic!("an observable type ace4 doesn't have: {}", o["type"])
                    }),
                value: o["value"].as_str().unwrap_or_default().to_owned(),
                tags: strings(&o["tags"]),
                directives: strings(&o["directives"]),
                detections: o["detections"].as_array().map_or(0, |d| d.len() as u32),
                paths: o["paths"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| TreePath {
                        path: p["path"].as_str().unwrap_or_default().to_owned(),
                        yara_meta: strings(&p["yara_meta"]),
                    })
                    .collect(),
                size: o["size"].as_u64(),
                pending: Vec::new(),
                download: None,
            })
            .collect();
        let results = view["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| !leave_out.contains(&r["class"].as_str().unwrap_or_default()))
            .map(|r| TreeResult {
                observable: r["observable"].as_u64().unwrap_or_default() as usize,
                module: r["module"].as_str().unwrap_or_default().to_owned(),
                analysis_type: ace3_analysis_type(r["class"].as_str().unwrap_or_default()),
                tags: strings(&r["tags"]),
                added: r["added"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|a| TreeAddition {
                        observable: a["observable"].as_u64().unwrap_or_default() as usize,
                        path: a["path"].as_str().map(str::to_owned),
                    })
                    .collect(),
            })
            .collect();
        TreeView {
            alert_type: view["alert_type"].as_str().map(str::to_owned),
            whitelisted: view["whitelisted"].as_bool().unwrap_or_default(),
            this,
            observables,
            results,
            truncated: false,
        }
    }

    /// The HTML bodies the dump kept with its root, by sha256.
    pub fn tree_bodies(&self) -> Vec<(String, Vec<u8>)> {
        use base64::Engine;
        self.value["tree_view"]["bodies"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(sha256, body)| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(body.as_str()?)
                    .ok()?;
                Some((sha256.clone(), bytes))
            })
            .collect()
    }

    /// The results of ace3 class `class` in the root the dump kept, each with its observable's index.
    pub fn tree_results(&self, class: &str) -> Vec<(usize, &Value)> {
        self.value["tree_view"]["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["class"] == class)
            .map(|r| (r["observable"].as_u64().unwrap_or_default() as usize, r))
            .collect()
    }

    /// The dump of ace3 class `class` in the normal form. Null when ace3 made no analysis.
    pub fn normal_form(&self, class: &str) -> Value {
        let Some(analysis) = self.analysis(class) else {
            return Value::Null;
        };
        let after = &self.value["observable_after"];
        let input = &self.value["input"];
        // what the module added to the observable it analyzed: what's there after the run that
        // wasn't there before
        let before_tags: BTreeSet<String> = strings(&input["meta_tags"])
            .into_iter()
            .chain(strings(&input["directives"]))
            .collect();
        // tags the run gave the input, as the module that added it would have
        let input_tags: BTreeSet<String> = strings(&input["tags"]).into_iter().collect();
        let analyzed = json!({
            "tags": set(
                strings(&after["tags"])
                    .into_iter()
                    .filter(|t| !input_tags.contains(t))
            ),
            "directives": set(
                ace3_directives(&after["directives"])
                    .into_iter()
                    .filter(|d| !before_tags.contains(d))
            ),
            "yara_meta": set(
                strings(&after["yara_meta"])
                    .into_iter()
                    .filter(|t| !before_tags.contains(t))
            ),
            "detections": ace3_detections(&after["detections"]),
        });
        let mut observables = Map::new();
        for observable in analysis["observables"].as_array().into_iter().flatten() {
            let (key, normal) = ace3_observable(observable);
            observables.insert(key, normal);
        }
        json!({
            "summary": analysis["summary"],
            "details": analysis["details"],
            "tags": set(strings(&analysis["tags"])),
            "detections": ace3_detections(&analysis["detections"]),
            "analyzed": analyzed,
            "observables": observables,
        })
    }
}

/// The ace4 analysis type of an ace3 analysis class, for those the modules that walk the tree look
/// for; any other is `ace3:<class>`.
pub fn ace3_analysis_type(class: &str) -> String {
    match class {
        "EmailAnalysis" => "email_analysis",
        "FileTypeAnalysis" => "file_type_analysis",
        "ProtectedURLAnalysis" => "protected_url_analysis",
        "EmailConversationFrequencyAnalysis" => "email_conversation_frequency_analysis",
        "LureURLAnalysis" => "lure_url_analysis",
        "MailboxEmailAnalysis" => "mailbox_email_analysis",
        "EmailConversationAttachmentAnalysis" => "email_conversation_attachment_analysis",
        "EmailConversationLinkAnalysis" => "email_conversation_link_analysis",
        other => return format!("ace3:{other}"),
    }
    .to_owned()
}

fn collect(dir: &Path, base: &Path, names: &mut Vec<String>) -> Result<(), HarnessError> {
    let entries =
        fs::read_dir(dir).map_err(|e| HarnessError::Fixture(format!("{}: {e}", dir.display())))?;
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            // RDAP's recorded HTTP exchanges sit beside its dumps
            if path.extension().is_none_or(|e| e != "http") {
                collect(&path, base, names)?;
            }
        } else if path.extension().is_some_and(|e| e == "json")
            // and the DNS module's recorded answers
            && !path.to_string_lossy().ends_with(".dns.json")
        {
            let relative = path.strip_prefix(base).unwrap_or(&path);
            let name = relative.to_string_lossy();
            // one suffix: a dump of `data.json` is `data.json.json`
            names.push(name.strip_suffix(".json").unwrap_or(&name).to_owned());
        }
    }
    Ok(())
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

fn set(items: impl IntoIterator<Item = String>) -> Value {
    Value::Object(items.into_iter().map(|i| (i, Value::Bool(true))).collect())
}

/// ace3's directives without the `yara_meta:` ones, which the normal form keeps as `yara_meta`.
fn ace3_directives(value: &Value) -> Vec<String> {
    strings(value)
        .into_iter()
        .filter(|d| !d.starts_with("yara_meta:"))
        .collect()
}

fn ace3_detections(value: &Value) -> Value {
    Value::Object(
        value
            .as_array()
            .into_iter()
            .flatten()
            .map(|d| {
                (
                    d["description"].as_str().unwrap_or_default().to_owned(),
                    d["details"].clone(),
                )
            })
            .collect(),
    )
}

/// The module name ace3 configures a class under, for `excluded_analysis`, which holds
/// `module:<class 'module.Class'>` strings.
fn ace3_module_name(excluded: &str) -> String {
    let class = excluded
        .rsplit('.')
        .next()
        .unwrap_or(excluded)
        .trim_end_matches("'>");
    match class {
        "EmailAnalyzer" => "email_analyzer",
        "MessageIDAnalyzerV2" => "message_id_analyzer_v2",
        "ArchiveAnalyzer" => "archive",
        "YaraScanner_v3_4" => "yara_scanner_v3_4",
        "IDNAAnalyzer" => "idna_analyzer",
        "HTMLDataURLAnalyzer" => "html_data_url_extraction",
        "HARExtractor" => "har_extraction",
        "HTMLJavaScriptExtractor" => "html_js_extraction",
        "MHTMLAnalysisModule" => "mhtml",
        "OCRAnalyzer" => "ocr",
        "FileHashAnalyzer" => "file_hash_analyzer",
        "FileTypeAnalyzer" => "file_type",
        "PDFAnalyzer" => "pdf_analyzer",
        "PDFTextAnalyzer" => "pdftotext",
        "ExifAnalyzer" => "exif",
        "QRCodeAnalyzer" => "qrcode",
        other => other,
    }
    .to_owned()
}

/// ace3 writes times with `str(datetime)`, such as `2020-05-28 14:53:51+00:00`.
fn ace3_time(text: &str) -> Value {
    DateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f%:z")
        .map(|t| {
            json!(
                t.with_timezone(&Utc)
                    .to_rfc3339_opts(SecondsFormat::AutoSi, true)
            )
        })
        .unwrap_or_else(|_| json!(text))
}

fn ace3_observable(o: &Value) -> (String, Value) {
    let kind = o["type"].as_str().unwrap_or_default();
    let key = if kind == "file" {
        format!("file:{}", o["file_path"].as_str().unwrap_or_default())
    } else {
        format!("{kind}:{}", o["value"].as_str().unwrap_or_default())
    };
    let mut normal = json!({
        "tags": set(strings(&o["tags"])),
        "directives": set(ace3_directives(&o["directives"])),
        "yara_meta": set(strings(&o["yara_meta"])),
        "detections": ace3_detections(&o["detections"]),
        "relationships": set(o["relationships"].as_array().into_iter().flatten().map(|r| {
            format!(
                "{} {}:{}",
                r["type"].as_str().unwrap_or_default(),
                r["target"]["type"].as_str().unwrap_or_default(),
                r["target"]["value"].as_str().unwrap_or_default()
            )
        })),
        "excluded_analysis": set(
            strings(&o["excluded_analysis"])
                .iter()
                .map(|e| ace3_module_name(e))
        ),
    });
    if let Some(time) = o["time"].as_str() {
        normal["time"] = ace3_time(time);
    }
    if let Some(redirection) = o.get("redirection") {
        normal["redirection"] = json!(format!(
            "{}:{}",
            redirection["type"].as_str().unwrap_or_default(),
            redirection["value"].as_str().unwrap_or_default()
        ));
    }
    if let Some(display_type) = o.get("display_type") {
        normal["display_type"] = display_type.clone();
    }
    if kind == "file" {
        normal["sha256"] = o["value"].clone();
        normal["size"] = o["size"].clone();
    }
    (key, normal)
}

fn ace4_detections(detections: &[Detection]) -> Value {
    Value::Object(
        detections
            .iter()
            .map(|d| {
                (
                    d.description.clone(),
                    d.details.clone().unwrap_or(Value::Null),
                )
            })
            .collect(),
    )
}

fn ace4_additions(additions: &ObservableAdditions) -> Value {
    json!({
        "tags": set(additions.tags.iter().cloned()),
        "directives": set(additions.directives.iter().cloned()),
        "yara_meta": set(additions.yara_meta.iter().map(|t| t.to_string())),
        "detections": ace4_detections(&additions.detections),
    })
}

fn ace4_links(
    relationships: &[ace_results::Relationship],
    redirection: &Option<ace_results::ObservableRef>,
    normal: &mut Value,
) {
    normal["relationships"] = set(relationships.iter().map(|r| {
        let kind = serde_json::to_value(r.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        format!("{kind} {}:{}", r.target.kind, r.target.value)
    }));
    if let Some(redirection) = redirection {
        normal["redirection"] = json!(format!("{}:{}", redirection.kind, redirection.value));
    }
}

fn ace4_observable(o: &NewObservable) -> (String, Value) {
    let mut normal = json!({
        "tags": set(o.tags.iter().cloned()),
        "directives": set(o.directives.iter().cloned()),
        "yara_meta": set(Vec::new()),
        "detections": ace4_detections(&o.detections),
        "excluded_analysis": set(o.exclude_modules.iter().cloned()),
    });
    ace4_links(&o.relationships, &o.redirection, &mut normal);
    if let Some(display_type) = &o.display_type {
        normal["display_type"] = json!(display_type);
    }
    if let Some(time) = o.time {
        normal["time"] = json!(time.to_rfc3339_opts(SecondsFormat::AutoSi, true));
    }
    (format!("{}:{}", o.kind, o.value), normal)
}

fn ace4_file(f: &NewFile) -> (String, Value) {
    let mut normal = json!({
        "tags": set(f.tags.iter().cloned()),
        "directives": set(f.directives.iter().cloned()),
        "yara_meta": set(f.yara_meta.iter().map(|t| t.to_string())),
        "detections": ace4_detections(&f.detections),
        "excluded_analysis": set(f.exclude_modules.iter().cloned()),
        "sha256": f.sha256.to_hex(),
        "size": f.size,
    });
    ace4_links(&f.relationships, &f.redirection, &mut normal);
    (format!("file:{}", f.path), normal)
}

/// ace4's outcome in the normal form. Null when it stored no result.
pub fn normal_form<D: AnalysisType>(outcome: &Outcome<D>) -> Value {
    let Outcome::Done(result) = outcome else {
        return Value::Null;
    };
    let mut observables = Map::new();
    for observable in &result.observables {
        let (key, normal) = ace4_observable(observable);
        observables.insert(key, normal);
    }
    for file in &result.files {
        let (key, normal) = ace4_file(file);
        observables.insert(key, normal);
    }
    json!({
        "summary": result.summary,
        "details": serde_json::to_value(&result.details)
            .unwrap_or_else(|e| json!({"unserializable": e.to_string()})),
        "tags": set(result.tags.iter().cloned()),
        "detections": ace4_detections(&result.detections),
        "analyzed": ace4_additions(&result.analyzed),
        "observables": observables,
    })
}
