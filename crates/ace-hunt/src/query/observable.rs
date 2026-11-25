//! An observable a hunt makes, and what ace3's observable classes do to a value when one is made
//! (`saq.observables.generator.create_observable`): some refuse a value, which drops the
//! observable, and some change it. The rules are `ace_sdk::observable_rules`', which the core
//! applies to every observable too.

use std::borrow::Cow;

use ace_results::ObservableKind;
use chrono::{DateTime, Utc};
use serde::Serialize;

/// An observable as a hunt submits it, the fields of ace3's `Observable` that a hunt sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observable {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    #[serde(serialize_with = "py_time")]
    pub time: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub directives: Vec<String>,
    pub display_type: Option<String>,
    pub display_value: Option<String>,
    pub volatile: bool,
    pub relationships: Vec<Relationship>,
}

fn py_time<S: serde::Serializer>(time: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
    match time {
        Some(t) => s.serialize_str(&crate::query::isoformat(t)),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Relationship {
    #[serde(rename = "type")]
    pub kind: String,
    pub target: Target,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

impl Observable {
    /// `create_observable`: None when the type's class refuses the value.
    pub fn create(kind: &str, value: &str, volatile: bool) -> Option<Observable> {
        Some(Observable {
            kind: kind.to_owned(),
            value: normalize(kind, value)?,
            time: None,
            tags: Vec::new(),
            directives: Vec::new(),
            display_type: None,
            display_value: None,
            volatile,
            relationships: Vec::new(),
        })
    }

    /// ace3's `Observable.__eq__`: the same type and value, compared without case for a caseless
    /// type, and the same time when either has one.
    pub fn same(&self, other: &Observable) -> bool {
        self.kind == other.kind
            && self.time == other.time
            && same_value(&self.kind, &self.value, &other.value)
    }

    /// `add_tag`, which keeps one of each.
    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.iter().any(|t| t == tag) {
            self.tags.push(tag.to_owned());
        }
    }

    /// `add_directive`, which keeps one of each.
    pub fn add_directive(&mut self, directive: &str) {
        if !self.directives.iter().any(|d| d == directive) {
            self.directives.push(directive.to_owned());
        }
    }
}

/// The types whose class is a `CaselessObservable`.
fn caseless(kind: &str) -> bool {
    matches!(kind, "email_address" | "asset" | "md5" | "sha1" | "sha256")
}

/// `CaselessObservable._compare_value`: both casefolded. Python also NFKD-normalizes, which only
/// matters for values outside ASCII; those are compared lowercased.
pub fn same_value(kind: &str, a: &str, b: &str) -> bool {
    if caseless(kind) {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

/// What the type's class keeps of `value`, or None when it refuses it. A type ace-rs doesn't know
/// has no class, so its value is kept as it is.
pub fn normalize(kind: &str, value: &str) -> Option<String> {
    match kind.parse::<ObservableKind>() {
        Ok(kind) => ace_sdk::observable_rules::class_value(kind, value)
            .ok()
            .map(Cow::into_owned),
        Err(_) => Some(value.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_kept_or_refused_as_ace3_s_classes_do() {
        assert_eq!(normalize("ip", " 10.1.2.3 ").as_deref(), Some("10.1.2.3"));
        assert_eq!(normalize("ip", "not-an-ip"), None);
        assert_eq!(normalize("ip", "010.1.2.3"), None);
        assert_eq!(normalize("ip", "::1").as_deref(), Some("::1"));
        assert_eq!(normalize("ipv4", " 10.1.2.3"), None);
        assert_eq!(normalize("user", "CORP\\alice").as_deref(), Some("alice"));
        assert_eq!(normalize("message_id", "a@b").as_deref(), Some("<a@b>"));
        assert_eq!(normalize("message_id", "nope"), None);
        assert_eq!(
            normalize("fqdn", "www.example.com").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(normalize("fqdn", "not a domain"), None);
        assert_eq!(normalize("fqdn", "a__b.com"), None);
        assert_eq!(
            normalize("url", " https://example.com/x ").as_deref(),
            Some(" https://example.com/x ")
        );
        assert_eq!(normalize("url", "https:/\\.."), None);
        assert_eq!(normalize("url", "mailto:x"), Some("mailto:x".to_owned()));
        assert_eq!(
            normalize(
                "sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            None
        );
        assert_eq!(normalize("md5", "0000"), None);
        assert_eq!(normalize("sha1", " abc ").as_deref(), Some("abc"));
        assert_eq!(normalize("file_location", "host@"), None);
        assert_eq!(normalize("command_line", " x ").as_deref(), Some(" x "));
    }
}
