//! 6.2's comparison with ace3: each hunt's normal form, the diff against what ace3's loader made
//! of the same files (`tools/ace3/hunts/make-hunts`), and the rows of
//! `tools/ace3/hunts/differences.md` that explain a difference.
//!
//! A hunt's normal form is what `tools/ace3/hunts/load_hunts.py` writes for it: its path under the
//! root, its type, and either `loaded` (the config as pydantic dumps it, the predefined commands,
//! the files read and the query file's text) or `error` (the exception's class and text, or for a
//! validation error the model and each error's type, location and message). Every string has the
//! root replaced by `$ROOT`.

use std::path::{Path, PathBuf};

use serde_json::{Map as JsonMap, Value as Json, json};

use crate::HuntError;
use crate::loader::LoadOptions;
use crate::manager::{LoadedHunt, load_hunts};
use crate::types::HuntType;

/// A hunt type and its rule directories, relative to the root.
pub struct RuleDirs<'a> {
    pub kind: &'a dyn HuntType,
    pub dirs: Vec<String>,
}

/// Every hunt under `root` in its normal form.
pub fn normal_form(root: &Path, types: &[RuleDirs<'_>], options: &LoadOptions) -> Json {
    let mut hunts = Vec::new();
    for rule_dirs in types {
        let dirs: Vec<PathBuf> = rule_dirs
            .dirs
            .iter()
            .map(|d| PathBuf::from(crate::paths::join(&root.to_string_lossy(), d)))
            .collect();
        for loaded in load_hunts(rule_dirs.kind, &dirs, options) {
            hunts.push(entry(root, rule_dirs.kind.name(), &loaded));
        }
    }
    json!({ "hunts": hunts })
}

fn entry(root: &Path, kind: &str, loaded: &LoadedHunt) -> Json {
    let root_text = root.to_string_lossy();
    let path = loaded
        .path
        .strip_prefix(root)
        .unwrap_or(&loaded.path)
        .to_string_lossy()
        .into_owned();
    let mut out = JsonMap::new();
    out.insert("path".to_owned(), Json::String(path));
    out.insert("type".to_owned(), Json::String(kind.to_owned()));
    match &loaded.result {
        Ok(hunt) => {
            let config = serde_json::to_value(&hunt.config).unwrap_or(Json::Null);
            let commands = serde_json::to_value(&hunt.commands).unwrap_or(Json::Null);
            out.insert(
                "loaded".to_owned(),
                json!({
                    "config": config,
                    "commands": commands,
                    "files": hunt.files,
                    "query": hunt.query_file,
                }),
            );
        }
        Err(error) => {
            out.insert("error".to_owned(), error_json(error));
        }
    }
    relative(Json::Object(out), &root_text)
}

/// An error in the normal form.
pub fn error_json(error: &HuntError) -> Json {
    match error {
        HuntError::Python { class, message } => json!({ "class": class, "message": message }),
        HuntError::Validation { title, errors } => json!({
            "class": "ValidationError",
            "title": title,
            "errors": errors.iter().map(|e| json!({
                "type": e.kind,
                "loc": e.loc.iter().map(|l| l.to_json()).collect::<Vec<_>>(),
                "msg": e.msg,
            })).collect::<Vec<_>>(),
        }),
        HuntError::Limit(message) => json!({ "class": "ace4 limit", "message": message }),
    }
}

fn relative(value: Json, root: &str) -> Json {
    match value {
        Json::String(s) => Json::String(s.replace(root, "$ROOT")),
        Json::Array(items) => Json::Array(items.into_iter().map(|v| relative(v, root)).collect()),
        Json::Object(map) => Json::Object(
            map.into_iter()
                .map(|(k, v)| (k.replace(root, "$ROOT"), relative(v, root)))
                .collect(),
        ),
        other => other,
    }
}

/// One place where ace4's normal form of a hunt isn't ace3's.
#[derive(Debug, Clone, PartialEq)]
pub struct Difference {
    /// The hunt's path under the root.
    pub hunt: String,
    /// A JSON pointer into the hunt's entry; empty when one side has no such hunt.
    pub pointer: String,
    pub ace3: Option<Json>,
    pub ace4: Option<Json>,
}

/// Every difference between ace3's normal form (`reference`) and ace4's (`ours`).
pub fn diff(reference: &Json, ours: &Json) -> Vec<Difference> {
    let by_path = |v: &Json| -> Vec<(String, Json)> {
        v["hunts"]
            .as_array()
            .map(|hunts| {
                hunts
                    .iter()
                    .map(|h| (h["path"].as_str().unwrap_or("").to_owned(), h.clone()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let theirs = by_path(reference);
    let mine = by_path(ours);
    let mut out = Vec::new();
    for (path, hunt) in &theirs {
        match mine.iter().find(|(p, _)| p == path) {
            Some((_, other)) => walk(path, "", hunt, other, &mut out),
            None => out.push(Difference {
                hunt: path.clone(),
                pointer: String::new(),
                ace3: Some(hunt.clone()),
                ace4: None,
            }),
        }
    }
    for (path, hunt) in &mine {
        if !theirs.iter().any(|(p, _)| p == path) {
            out.push(Difference {
                hunt: path.clone(),
                pointer: String::new(),
                ace3: None,
                ace4: Some(hunt.clone()),
            });
        }
    }
    out
}

fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn walk(hunt: &str, pointer: &str, a: &Json, b: &Json, out: &mut Vec<Difference>) {
    match (a, b) {
        (Json::Object(x), Json::Object(y)) => {
            for (k, v) in x {
                let p = format!("{pointer}/{}", escape(k));
                match y.get(k) {
                    Some(w) => walk(hunt, &p, v, w, out),
                    None => out.push(Difference {
                        hunt: hunt.to_owned(),
                        pointer: p,
                        ace3: Some(v.clone()),
                        ace4: None,
                    }),
                }
            }
            for (k, w) in y {
                if !x.contains_key(k) {
                    out.push(Difference {
                        hunt: hunt.to_owned(),
                        pointer: format!("{pointer}/{}", escape(k)),
                        ace3: None,
                        ace4: Some(w.clone()),
                    });
                }
            }
        }
        (Json::Array(x), Json::Array(y)) => {
            for i in 0..x.len().max(y.len()) {
                let p = format!("{pointer}/{i}");
                match (x.get(i), y.get(i)) {
                    (Some(v), Some(w)) => walk(hunt, &p, v, w, out),
                    (v, w) => out.push(Difference {
                        hunt: hunt.to_owned(),
                        pointer: p,
                        ace3: v.cloned(),
                        ace4: w.cloned(),
                    }),
                }
            }
        }
        _ if a == b => {}
        _ => out.push(Difference {
            hunt: hunt.to_owned(),
            pointer: pointer.to_owned(),
            ace3: Some(a.clone()),
            ace4: Some(b.clone()),
        }),
    }
}

/// A row of differences.md: the set of hunts it's for (`cases` or `signatures`), the hunts it
/// covers, the path it covers in each, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub set: String,
    pub hunts: String,
    pub path: String,
    pub why: String,
}

/// The rows of a differences table for one set: `| Set | Hunts | Path | Why |`, the hunts and
/// paths in backticks.
pub fn parse_rows(markdown: &str, set: &str) -> Vec<Row> {
    let mut rows = Vec::new();
    for line in markdown.lines() {
        let line = line.trim();
        if !line.starts_with('|') || line.starts_with("|---") || line.starts_with("| Set") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split(" | ").map(str::trim).collect();
        if cells.len() < 4 || cells[0] != set {
            continue;
        }
        let unquote = |s: &str| s.trim_matches('`').to_owned();
        rows.push(Row {
            set: cells[0].to_owned(),
            hunts: unquote(cells[1]),
            path: unquote(cells[2]),
            why: cells[3].to_owned(),
        });
    }
    rows
}

/// Whether `text` matches `pattern`, where `*` is any text.
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut rest = text;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            let Some(r) = rest.strip_prefix(part) else {
                return false;
            };
            rest = r;
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

/// Whether a JSON pointer matches a row's path, where a `*` segment is one segment, `**` any
/// number, and a `*` inside a segment any text.
fn pointer_matches(pattern: &str, pointer: &str) -> bool {
    fn segments(p: &str) -> Vec<&str> {
        p.split('/').skip(1).collect()
    }
    fn go(pattern: &[&str], pointer: &[&str]) -> bool {
        match pattern.split_first() {
            None => pointer.is_empty(),
            Some((&"**", rest)) => (0..=pointer.len()).any(|i| go(rest, &pointer[i..])),
            Some((first, rest)) => pointer
                .split_first()
                .is_some_and(|(p, tail)| glob(first, p) && go(rest, tail)),
        }
    }
    go(&segments(pattern), &segments(pointer))
}

/// The differences no row explains, and the rows that explain none.
pub struct Report {
    pub explained: usize,
    pub unexplained: Vec<Difference>,
    pub unused: Vec<Row>,
}

pub fn classify(differences: Vec<Difference>, rows: &[Row]) -> Report {
    let mut used = vec![false; rows.len()];
    let mut unexplained = Vec::new();
    let mut explained = 0;
    for difference in differences {
        let row = rows.iter().position(|r| {
            glob(&r.hunts, &difference.hunt) && pointer_matches(&r.path, &difference.pointer)
        });
        match row {
            Some(i) => {
                used[i] = true;
                explained += 1;
            }
            None => unexplained.push(difference),
        }
    }
    let unused = rows
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|(r, _)| r.clone())
        .collect();
    Report {
        explained,
        unexplained,
        unused,
    }
}

impl std::fmt::Display for Difference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let show = |v: &Option<Json>| {
            v.as_ref().map_or("(none)".to_owned(), |v| {
                let text = v.to_string();
                if text.len() > 300 {
                    format!("{}...", &text[..text.floor_char_boundary(300)])
                } else {
                    text
                }
            })
        };
        write!(
            f,
            "{} {}\n  ace3: {}\n  ace4: {}",
            self.hunt,
            if self.pointer.is_empty() {
                "(the whole hunt)"
            } else {
                &self.pointer
            },
            show(&self.ace3),
            show(&self.ace4)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Logscale, Rapid7, Splunk};

    /// tools/ace3/hunts, beside this crate.
    fn hunts_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/hunts")
    }

    /// The Done check's half that runs anywhere: the hunts written for the comparison, each of
    /// ace3's errors among them, load as ace3's loader loaded them, but where differences.md
    /// says why not. tools/ace3/hunts/compare runs the same over the signatures.
    #[test]
    fn the_cases_load_as_they_do_in_ace3() {
        let dir = hunts_dir();
        let root = dir.join("cases").canonicalize().unwrap();
        let reference: Json =
            serde_json::from_slice(&std::fs::read(dir.join("reference/cases.json")).unwrap())
                .unwrap();
        let rows = parse_rows(
            &std::fs::read_to_string(dir.join("differences.md")).unwrap(),
            "cases",
        );
        let splunk = Splunk {
            instances: Some(vec!["default".to_owned()]),
        };
        let types = [
            RuleDirs {
                kind: &splunk,
                dirs: vec!["hunts/splunk".to_owned()],
            },
            RuleDirs {
                kind: &Logscale,
                dirs: vec!["hunts/logscale".to_owned()],
            },
            RuleDirs {
                kind: &Rapid7,
                dirs: vec!["hunts/rapid7".to_owned()],
            },
        ];
        let ours = normal_form(&root, &types, &LoadOptions::default());
        let report = classify(diff(&reference, &ours), &rows);
        let unexplained: Vec<String> = report.unexplained.iter().map(ToString::to_string).collect();
        assert!(unexplained.is_empty(), "{}", unexplained.join("\n"));
        assert!(
            report.unused.is_empty(),
            "rows that match nothing in the cases: {:?}",
            report.unused
        );
        assert_eq!(
            ours["hunts"].as_array().map(Vec::len),
            reference["hunts"].as_array().map(Vec::len)
        );
    }

    #[test]
    fn pointers_match_rows_as_the_trees_do() {
        assert!(pointer_matches("/error/message", "/error/message"));
        assert!(pointer_matches("/loaded/**", "/loaded/config/a/0"));
        assert!(pointer_matches("/loaded/*/files", "/loaded/x/files"));
        assert!(!pointer_matches("/error/*", "/error/a/b"));
        assert!(glob("hunts/splunk/*", "hunts/splunk/a.yaml"));
        assert!(glob("*loop*", "hunts/splunk/include_spelled_loop.yaml"));
    }
}
