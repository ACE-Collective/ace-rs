//! `lnk_parser`: ace3's `LnkParseAnalyzer` (`saq/modules/file_analysis/lnk_parser.py`), on
//! `ace-lnkparse`, the port of LnkParse3 1.6.0.
//!
//! A file that starts with the shortcut header is tagged `lnk` and gets a result: LnkParse3's
//! JSON, or the exception it raised. When nothing raised, the JSON is also written to
//! `{file}.lnkparser.json` with the `yara_meta` type `metadata.lnk`, which YARA rules scan.

use std::fs;

use ace_results::FileRole;
use ace_results::types::lnk::LnkParseAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use serde_json::Value;

use ace_sdk::takes::{Condition, Takes, TypeFact};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<LnkParseAnalyzer>();

pub struct LnkParseAnalyzer;

impl Module for LnkParseAnalyzer {
    const NAME: &'static str = LnkParseAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = LnkParseAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(LnkParseAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        // the file's type says it, as `checks::is_lnk_file` on the bytes did (PLAN.md decision 25)
        Takes::everything().and(
            Condition::type_fact(TypeFact::IsLnkFile),
            "not a Windows shortcut",
        )
    }
}

/// Python's `ntpath.splitroot`.
fn splitroot(p: &str) -> (&str, &str, &str) {
    let is_sep = |c: Option<char>| matches!(c, Some('\\') | Some('/'));
    let mut chars = p.chars();
    let first = chars.next();
    let second = chars.next();
    if is_sep(first) {
        if !is_sep(second) {
            return ("", &p[..1], &p[1..]);
        }
        // a UNC path, \\server\share
        let norm = p.replace('/', "\\");
        let start = if norm.len() >= 8 && norm[..8].eq_ignore_ascii_case("\\\\?\\UNC\\") {
            8
        } else {
            2
        };
        let Some(index) = norm[start..].find('\\').map(|i| i + start) else {
            return (p, "", "");
        };
        let Some(index2) = norm[index + 1..].find('\\').map(|i| i + index + 1) else {
            return (p, "", "");
        };
        return (&p[..index2], &p[index2..index2 + 1], &p[index2 + 1..]);
    }
    if second == Some(':') {
        let drive_end = first.map_or(0, char::len_utf8) + 1;
        let rest = &p[drive_end..];
        if is_sep(rest.chars().next()) {
            return (&p[..drive_end], &rest[..1], &rest[1..]);
        }
        return (&p[..drive_end], "", rest);
    }
    ("", "", p)
}

/// Python's `ntpath.join`.
pub fn ntpath_join(parts: &[String]) -> String {
    let Some((first, rest)) = parts.split_first() else {
        return String::new();
    };
    let (d, r, p) = splitroot(first);
    let (mut drive, mut root, mut path) = (d.to_owned(), r.to_owned(), p.to_owned());
    for part in rest {
        let (p_drive, p_root, p_path) = splitroot(part);
        if !p_root.is_empty() {
            if !p_drive.is_empty() || drive.is_empty() {
                drive = p_drive.to_owned();
            }
            root = p_root.to_owned();
            path = p_path.to_owned();
            continue;
        } else if !p_drive.is_empty() && p_drive != drive {
            if p_drive.to_lowercase() != drive.to_lowercase() {
                drive = p_drive.to_owned();
                root = p_root.to_owned();
                path = p_path.to_owned();
                continue;
            }
            drive = p_drive.to_owned();
        }
        if !path.is_empty() && !path.ends_with(['\\', '/']) {
            path.push('\\');
        }
        path.push_str(p_path);
    }
    if !path.is_empty()
        && root.is_empty()
        && !drive.is_empty()
        && !drive.ends_with([':', '\\', '/'])
    {
        return format!("{drive}\\{path}");
    }
    format!("{drive}{root}{path}")
}

fn truthy_str(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// `get_target_path`: the volume, then each file entry's name, joined as a Windows path.
pub fn target_path(info: &Value) -> Option<String> {
    let items = info.get("target")?.get("items")?.as_array()?;
    let mut parts: Vec<String> = Vec::new();
    for item in items {
        let Some(item) = item.as_object() else {
            continue;
        };
        match item.get("class").and_then(Value::as_str) {
            Some("Volume Item") => {
                if let Some(name) =
                    truthy_str(item.get("data")).or_else(|| truthy_str(item.get("volume_name")))
                {
                    parts.insert(0, name.to_owned());
                }
            }
            Some("File entry") => {
                if let Some(name) = truthy_str(item.get("primary_name")) {
                    parts.push(name.to_owned());
                }
            }
            _ => {}
        }
    }
    (!parts.is_empty()).then(|| ntpath_join(&parts))
}

/// `generate_summary`, with the result's error.
pub fn summary(details: &LnkParseAnalysis, error: Option<&str>) -> Option<String> {
    const NAME: &str = "LnkParse Analysis";
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        return Some(format!("{NAME}: {error}"));
    }
    let info = &details.info;
    let data = info.get("data");
    let mut parts = Vec::new();
    if let Some(path) = target_path(info).filter(|p| !p.is_empty()) {
        parts.push(format!("target path: ({path})"));
    }
    for (key, label) in [
        ("command_line_arguments", "command line arguments"),
        ("icon_location", "icon location"),
        ("working_directory", "working directory"),
    ] {
        if let Some(value) = truthy_str(data.and_then(|d| d.get(key))) {
            parts.push(format!("{label}: ({value})"));
        }
    }
    (!parts.is_empty()).then(|| format!("{NAME}: {}", parts.join(", ")))
}

impl Parser for LnkParseAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<LnkParseAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = fs::read(&file.local_path)?;
        ctx.check_cancelled()?;
        let parsed = ace_lnkparse::analyze(&data);
        let details = LnkParseAnalysis {
            info: ace_lnkparse::to_ace3_json(&parsed.info),
        };
        // lnk_parser.py's `str(e) or type(e).__name__` of what LnkParse3 raised
        let error = parsed.error.as_ref().map(|e| {
            if e.message.trim().is_empty() {
                e.kind.to_owned()
            } else {
                e.message.clone()
            }
        });
        let summary = summary(&details, error.as_deref());
        let mut result = ResultEnvelope::new(details);
        result.summary = summary;
        result.error = error;
        result.analyzed.add_tag("lnk");
        if let Some(text) = parsed.lnkparser_json {
            let path = format!("{}.lnkparser.json", file.path.as_str());
            result
                .files
                .push(ctx.write_file(&path, text.as_bytes(), FileRole::METADATA_LNK)?);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntpath_joins_as_python_does() {
        let join = |parts: &[&str]| {
            ntpath_join(&parts.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(join(&["C:\\", "Users", "a.exe"]), "C:\\Users\\a.exe");
        assert_eq!(join(&["C:", "Users"]), "C:Users");
        assert_eq!(join(&["a", "\\b"]), "\\b");
        assert_eq!(join(&["\\\\srv\\share", "x"]), "\\\\srv\\share\\x");
        assert_eq!(join(&["Users", "a"]), "Users\\a");
    }
}
