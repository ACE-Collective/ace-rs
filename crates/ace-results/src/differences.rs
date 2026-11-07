//! Differences between two JSON forms by JSON pointer, and the `differences.md` tables that
//! explain them. A port's reference test (`ace-testkit`) and `ace compare` (PLAN.md 3.3) both use
//! these, so this holds no test tooling and reads no form of its own.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::Value;

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
    /// The `##` heading the row is under, if any.
    pub section: Option<String>,
    /// The row's fourth cell, a condition on the difference, for whoever reads conditions.
    /// `check` doesn't.
    pub when: Option<String>,
}

/// A `differences.md` that can't be read.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct UnreadableList(String);

/// The differences a port lists in its `tests/differences.md`.
#[derive(Debug, Clone)]
pub struct ListedDifferences {
    pub rows: Vec<Listed>,
}

impl ListedDifferences {
    /// Reads the table rows of a `differences.md`: `` | `<dumps>` | `<path>` | <why> | ``, with
    /// an optional fourth cell, `Listed::when`.
    /// `<dumps>` is a glob over dump names, and `<path>` a JSON pointer where a `*` segment is
    /// any one segment, `**` any number of them, and `*` inside a segment any text.
    pub fn load(path: &Path) -> Result<ListedDifferences, UnreadableList> {
        let text = fs::read_to_string(path)
            .map_err(|e| UnreadableList(format!("{}: {e}", path.display())))?;
        let mut rows = Vec::new();
        let mut section = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(heading) = line.strip_prefix("## ") {
                section = Some(heading.trim().to_owned());
            }
            if !line.starts_with("| `") {
                continue;
            }
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let [dumps, pattern, why, rest @ ..] = cells.as_slice() else {
                return Err(UnreadableList(format!(
                    "{}: a row needs three cells: {line}",
                    path.display()
                )));
            };
            rows.push(Listed {
                dumps: dumps.trim_matches('`').to_owned(),
                path: pattern.trim_matches('`').to_owned(),
                why: (*why).to_owned(),
                section: section.clone(),
                when: rest
                    .first()
                    .map(|when| when.trim_matches('`').to_owned())
                    .filter(|when| !when.is_empty()),
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
        self.check_between(compared, skipped, "ace3", "ace4")
    }

    /// `check`, for two sides that aren't ace3 and ace4, naming them in its report.
    pub fn check_between(
        &self,
        compared: &[(String, Vec<Difference>)],
        skipped: &[String],
        left: &str,
        right: &str,
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
                        "{dump}: {}\n    {left}: {}\n    {right}: {}",
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
/// (none included), and a `*` inside a segment globs within it. `/` alone is the whole result,
/// for a dump where only one side has a result at all.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/" {
        return path.is_empty();
    }
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
    use serde_json::json;

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
        assert!(path_matches("/", ""));
        assert!(!path_matches("/", "/details"));
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
