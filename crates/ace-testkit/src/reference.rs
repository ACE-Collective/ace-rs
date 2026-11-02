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
//! `sha256` and `size` when it has them. Sets are objects whose keys are the members, so a
//! difference names the member. ace3 keeps `yara_meta` tags among the directives as
//! `yara_meta:name=value`; the normal form keeps them only under `yara_meta`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ace_results::{AnalysisType, Detection, NewFile, NewObservable, ObservableAdditions};
use ace_sdk::Outcome;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};

use crate::HarnessError;

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

    /// The mime type ace3's file_type module gave the input.
    pub fn mime_type(&self) -> Option<&str> {
        self.analysis("FileTypeAnalysis")?["details"]["mime"].as_str()
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
        let analyzed = json!({
            "tags": set(strings(&after["tags"])),
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
        } else if path.extension().is_some_and(|e| e == "json") {
            let relative = path.strip_prefix(base).unwrap_or(&path);
            let name = relative.to_string_lossy();
            names.push(name.trim_end_matches(".json").to_owned());
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

/// One place where ace3's and ace4's normal forms differ. A side is None where it has nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct Difference {
    /// A JSON pointer into the normal form.
    pub path: String,
    pub ace3: Option<Value>,
    pub ace4: Option<Value>,
}

/// Every difference between two normal forms, by JSON pointer.
pub fn diff(ace3: &Value, ace4: &Value) -> Vec<Difference> {
    let mut out = Vec::new();
    diff_at(String::new(), Some(ace3), Some(ace4), &mut out);
    out
}

fn diff_at(path: String, a: Option<&Value>, b: Option<&Value>, out: &mut Vec<Difference>) {
    match (a, b) {
        (Some(Value::Object(a)), Some(Value::Object(b))) => {
            let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for key in keys {
                diff_at(
                    format!("{path}/{}", escape(key)),
                    a.get(key),
                    b.get(key),
                    out,
                );
            }
        }
        (Some(Value::Array(a)), Some(Value::Array(b))) => {
            for i in 0..a.len().max(b.len()) {
                diff_at(format!("{path}/{i}"), a.get(i), b.get(i), out);
            }
        }
        (a, b) if a == b => {}
        (a, b) => out.push(Difference {
            path,
            ace3: a.cloned(),
            ace4: b.cloned(),
        }),
    }
}

/// A key as one JSON pointer segment (RFC 6901).
fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// One row of a `differences.md` table: the dumps it covers, the path pattern and why.
#[derive(Debug, Clone)]
pub struct Listed {
    pub dumps: String,
    pub path: String,
    pub why: String,
}

/// The differences a port lists in its `tests/differences.md`.
#[derive(Debug, Clone)]
pub struct ListedDifferences {
    pub rows: Vec<Listed>,
}

impl ListedDifferences {
    /// Reads the table rows of a `differences.md`: `` | `<dumps>` | `<path>` | <why> | ``.
    /// `<dumps>` is a glob over dump names, and `<path>` a JSON pointer where a `*` segment is
    /// any one segment, `**` any number of them, and `*` inside a segment any text.
    pub fn load(path: &Path) -> Result<ListedDifferences, HarnessError> {
        let text = fs::read_to_string(path)
            .map_err(|e| HarnessError::Fixture(format!("{}: {e}", path.display())))?;
        let mut rows = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("| `") {
                continue;
            }
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let [dumps, pattern, why, ..] = cells.as_slice() else {
                return Err(HarnessError::Fixture(format!(
                    "{}: a row needs three cells: {line}",
                    path.display()
                )));
            };
            rows.push(Listed {
                dumps: dumps.trim_matches('`').to_owned(),
                path: pattern.trim_matches('`').to_owned(),
                why: (*why).to_owned(),
            });
        }
        Ok(ListedDifferences { rows })
    }

    /// Checks every difference of every dump against the list. Fails with a report when a
    /// difference isn't listed, or a row matched nothing in the dumps compared. `skipped` names
    /// dumps that couldn't be compared, such as those of git-ignored local samples; a row that
    /// covers only those isn't stale.
    pub fn check(
        &self,
        compared: &[(String, Vec<Difference>)],
        skipped: &[String],
    ) -> Result<(), String> {
        let mut used = vec![false; self.rows.len()];
        let mut unexplained = Vec::new();
        for (dump, differences) in compared {
            for difference in differences {
                let mut explained = false;
                for (i, row) in self.rows.iter().enumerate() {
                    if glob(&row.dumps, dump) && path_matches(&row.path, &difference.path) {
                        used[i] = true;
                        explained = true;
                    }
                }
                if !explained {
                    unexplained.push(format!(
                        "{dump}: {}\n    ace3: {}\n    ace4: {}",
                        difference.path,
                        show(&difference.ace3),
                        show(&difference.ace4)
                    ));
                }
            }
        }
        let stale: Vec<String> = self
            .rows
            .iter()
            .zip(&used)
            .filter(|(row, used)| {
                let only_skipped = !compared.iter().any(|(dump, _)| glob(&row.dumps, dump))
                    && skipped.iter().any(|dump| glob(&row.dumps, dump));
                !**used && !only_skipped
            })
            .map(|(row, _)| format!("{} {}", row.dumps, row.path))
            .collect();
        if unexplained.is_empty() && stale.is_empty() {
            return Ok(());
        }
        let mut report = String::new();
        if !unexplained.is_empty() {
            report.push_str(&format!(
                "{} differences aren't listed in differences.md:\n",
                unexplained.len()
            ));
            for line in &unexplained {
                report.push_str(line);
                report.push('\n');
            }
        }
        if !stale.is_empty() {
            report.push_str("rows in differences.md that matched nothing:\n");
            for line in &stale {
                report.push_str(line);
                report.push('\n');
            }
        }
        Err(report)
    }
}

fn show(value: &Option<Value>) -> String {
    match value {
        None => "(nothing)".to_owned(),
        Some(value) => {
            let text = value.to_string();
            if text.chars().count() > 300 {
                format!("{}...", text.chars().take(300).collect::<String>())
            } else {
                text
            }
        }
    }
}

/// A glob where `*` matches any text.
pub fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut rest = text;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(after) => rest = after,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Whether a JSON pointer matches a pattern: `*` is one segment, `**` any number of segments
/// (none included), and a `*` inside a segment globs within it.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').skip(1).collect();
    let path: Vec<&str> = path.split('/').skip(1).collect();
    segments_match(&pattern, &path)
}

fn segments_match(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|i| segments_match(rest, &path[i..])),
        Some((first, rest)) => match path.split_first() {
            Some((segment, path_rest)) => glob(first, segment) && segments_match(rest, path_rest),
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_match_patterns() {
        assert!(path_matches(
            "/details/email/log_entry/date",
            "/details/email/log_entry/date"
        ));
        assert!(path_matches(
            "/observables/*/tags/email",
            "/observables/file:x/tags/email"
        ));
        assert!(path_matches(
            "/observables/file:*.txt/size",
            "/observables/file:a.txt/size"
        ));
        assert!(path_matches("/details/**", "/details/a/b/0"));
        assert!(path_matches("/details/**/date", "/details/date"));
        assert!(!path_matches(
            "/observables/*/tags/email",
            "/observables/x/tags/pdf"
        ));
        assert!(!path_matches("/details", "/details/a"));
        assert!(glob(
            "ace3/email/o365*",
            "ace3/email/o365_journaled.email.rfc822"
        ));
        assert!(glob("*", "anything"));
    }

    #[test]
    fn differences_name_their_paths() {
        let a = json!({"x": {"a": 1, "b": [1, 2]}, "t": {"k": true}});
        let b = json!({"x": {"a": 2, "b": [1]}, "t": {}});
        let paths: Vec<String> = diff(&a, &b).into_iter().map(|d| d.path).collect();
        assert_eq!(paths, ["/t/k", "/x/a", "/x/b/1"]);
        let key = json!({"file:a/b": 1});
        assert_eq!(diff(&key, &json!({}))[0].path, "/file:a~1b");
    }
}
