//! The post-scan filter on meta directives, ported from `filter_scan_results` in
//! yara_scanner_v2 3.0.0.
//!
//! A rule's condition can match and the match still be dropped, when a directive in its meta
//! disagrees with the file. Five directives do this (DESIGN.md, *The YARA scanner*):
//!
//! | Directive | Compared against |
//! |---|---|
//! | `meta_tags` | each tag the caller passes for the file |
//! | `file_name` | the file's name: the path after its last `/` |
//! | `mime_type` | the file's mime type, from libmagic |
//! | `full_path` | the file's path |
//! | `file_ext` | everything after the last `.` of the whole path, or nothing |
//!
//! A directive's key is matched ignoring case. Its value is a comma-separated list and the
//! directive holds when any item matches. `!` first negates the list. Then `re:` makes each
//! item a regex search ignoring case, or `sub:` a substring test; plain items are compared
//! for equality ignoring case. A `meta_tags` list holds when any item matches any of the
//! caller's tags, and a non-negated one drops the match when the caller passes no tags.
//! Values that aren't strings are ignored.
//!
//! Three quirks of the Python are kept, because rules are written against them: the prefixes
//! are matched case-sensitively and before anything is trimmed; the whole value is lowercased
//! before it is split, regex items included, so `re:\D` searches for `\d`; and the value is
//! split on every comma, inside a regex too.

use std::collections::BTreeSet;
use std::fmt;

use regex::{Regex, RegexBuilder};

use crate::meta::{Meta, MetaValue};

/// What the filter compares a match's directives against.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// The file's path. In ace3 that is the absolute path on the node; in ace-rs it is the
    /// file's path inside the alert.
    pub path: &'a str,
    /// The file's mime type, as `file -b --mime-type` gives it.
    pub mime_type: &'a str,
    /// The `yara_meta` tags the caller passes for the file, such as `type=email.attachment`.
    pub meta_tags: &'a [String],
}

impl Target<'_> {
    /// Everything after the last `.` of the whole path, so a `.` in a directory counts.
    pub fn extension(&self) -> &str {
        self.path.rsplit_once('.').map_or("", |(_, ext)| ext)
    }

    /// The path after its last `/`.
    pub fn file_name(&self) -> &str {
        self.path
            .rsplit_once('/')
            .map_or(self.path, |(_, name)| name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectiveKind {
    MetaTags,
    FileName,
    MimeType,
    FullPath,
    FileExt,
}

impl DirectiveKind {
    pub fn from_key(key: &str) -> Option<Self> {
        match key.to_lowercase().as_str() {
            "meta_tags" => Some(Self::MetaTags),
            "file_name" => Some(Self::FileName),
            "mime_type" => Some(Self::MimeType),
            "full_path" => Some(Self::FullPath),
            "file_ext" => Some(Self::FileExt),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
enum Items {
    Equal(Vec<String>),
    Substring(Vec<String>),
    Regex(Vec<Regex>),
}

/// One directive of a rule, parsed from its meta.
#[derive(Debug, Clone)]
pub struct Directive {
    kind: DirectiveKind,
    negated: bool,
    items: Items,
}

/// A `re:` item that the regex crate can't compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidRegex {
    /// The meta key, as the rule writes it.
    pub key: String,
    /// The pattern as compiled: lowercased and trimmed, as the Python compiles it.
    pub pattern: String,
    /// The regex crate's reason, on one line.
    pub error: String,
}

impl fmt::Display for InvalidRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "meta {} has a re: pattern the regex crate can't compile, `{}`: {}",
            self.key, self.pattern, self.error
        )
    }
}

impl std::error::Error for InvalidRegex {}

/// The regex crate's parse errors repeat the pattern over several lines with a caret under
/// the problem, ending in an `error: ` line. Keeps that line, so a log entry stays one line.
fn one_line(error: &regex::Error) -> String {
    let text = error.to_string();
    let reason = text
        .lines()
        .find_map(|line| line.strip_prefix("error: "))
        .map(str::to_string);
    reason.unwrap_or_else(|| text.lines().collect::<Vec<_>>().join(" "))
}

impl Directive {
    /// Parses one meta entry. Returns `None` when the key isn't a directive or the value
    /// isn't a string.
    pub fn parse(key: &str, value: &MetaValue) -> Result<Option<Self>, InvalidRegex> {
        let Some(kind) = DirectiveKind::from_key(key) else {
            return Ok(None);
        };
        let value = match value {
            MetaValue::Str(s) => s.as_str(),
            _ => return Ok(None),
        };

        let (negated, value) = strip(value, "!");
        let (regex, value) = strip(value, "re:");
        let (substring, value) = strip(value, "sub:");

        let items: Vec<String> = value
            .to_lowercase()
            .split(',')
            .map(|item| item.trim().to_string())
            .collect();

        // re: wins when both prefixes are given, as in the Python.
        let items = if regex {
            let mut compiled = Vec::with_capacity(items.len());
            for pattern in items {
                match RegexBuilder::new(&pattern).case_insensitive(true).build() {
                    Ok(re) => compiled.push(re),
                    Err(e) => {
                        return Err(InvalidRegex {
                            key: key.to_string(),
                            pattern,
                            error: one_line(&e),
                        });
                    }
                }
            }
            Items::Regex(compiled)
        } else if substring {
            Items::Substring(items)
        } else {
            Items::Equal(items)
        };

        Ok(Some(Directive {
            kind,
            negated,
            items,
        }))
    }

    pub fn kind(&self) -> DirectiveKind {
        self.kind
    }

    fn item_matches(&self, candidate: &str) -> bool {
        match &self.items {
            Items::Equal(items) => items.contains(&candidate.to_lowercase()),
            Items::Substring(items) => {
                let candidate = candidate.to_lowercase();
                items.iter().any(|item| candidate.contains(item.as_str()))
            }
            Items::Regex(items) => items.iter().any(|re| re.is_match(candidate)),
        }
    }

    /// Whether this directive lets the match through.
    pub fn keeps(&self, target: &Target<'_>) -> bool {
        let matched = match self.kind {
            DirectiveKind::MetaTags => {
                if target.meta_tags.is_empty() {
                    // The rule asks for tags and the file has none: dropped, unless negated.
                    return self.negated;
                }
                target.meta_tags.iter().any(|tag| self.item_matches(tag))
            }
            DirectiveKind::FileName => self.item_matches(target.file_name()),
            DirectiveKind::MimeType => self.item_matches(target.mime_type),
            DirectiveKind::FullPath => self.item_matches(target.path),
            DirectiveKind::FileExt => self.item_matches(target.extension()),
        };
        matched != self.negated
    }
}

fn strip<'a>(value: &'a str, prefix: &str) -> (bool, &'a str) {
    match value.strip_prefix(prefix) {
        Some(rest) => (true, rest),
        None => (false, value),
    }
}

/// Every directive of one rule.
#[derive(Debug, Clone, Default)]
pub struct RuleFilter {
    directives: Vec<Directive>,
}

impl RuleFilter {
    pub fn from_meta(meta: &Meta) -> Result<Self, InvalidRegex> {
        let mut directives = Vec::new();
        for (key, value) in meta.iter() {
            if let Some(directive) = Directive::parse(key, value)? {
                directives.push(directive);
            }
        }
        Ok(RuleFilter { directives })
    }

    pub fn directives(&self) -> &[Directive] {
        &self.directives
    }

    /// Whether every directive lets the match through.
    pub fn keeps(&self, target: &Target<'_>) -> bool {
        self.directives.iter().all(|d| d.keeps(target))
    }
}

/// Whether a match of `rule` survives the filter: the rule isn't blacklisted and every
/// directive lets it through.
pub fn keeps(
    rule: &str,
    filter: &RuleFilter,
    blacklist: &BTreeSet<String>,
    target: &Target<'_>,
) -> bool {
    !blacklist.contains(rule) && filter.keeps(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_extension_is_taken_from_the_whole_path() {
        let target = |path| Target {
            path,
            mime_type: "",
            meta_tags: &[],
        };
        assert_eq!(target("a/b/report.PS1").extension(), "PS1");
        assert_eq!(target("a.d/noext").extension(), "d/noext");
        assert_eq!(target("a/noext").extension(), "");
        assert_eq!(target("a/b/report.PS1").file_name(), "report.PS1");
        assert_eq!(target("name").file_name(), "name");
    }
}
