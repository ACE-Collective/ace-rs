//! How ACE reads a rule's meta, ported from ace3's `saq/signatures/yara_meta.py`.
//!
//! The YARA module acts on a match's meta, and SVS reads the same meta to decide whether a
//! match would have made a detection (`saq/svs/yara/diff.py`), so both read it here:
//!
//! - `enabled`: a falsy value (`false`, `no`, `0`, `off` or `disabled`, as a string or a
//!   native value) drops every match of the rule as if it never matched.
//! - `uuid`: the rule's stable identifier.
//! - `modifiers`: a comma-separated list. `qa` puts the rule in QA mode and `no_alert` keeps
//!   it from alerting; SVS treats both as "never alerts".
//!
//! Meta values arrive as strings, integers, floats or booleans depending on how the author
//! wrote them (`enabled = false` or `enabled = "false"`), so each reading follows what
//! Python's `str()` and truthiness make of each kind.

use crate::meta::{Meta, MetaValue};

pub const META_ENABLED: &str = "enabled";
pub const META_MODIFIERS: &str = "modifiers";
pub const META_UUID: &str = "uuid";

pub const MODIFIER_QA: &str = "qa";
pub const MODIFIER_NO_ALERT: &str = "no_alert";

const FALSE_META_VALUES: [&str; 5] = ["false", "no", "0", "off", "disabled"];

impl MetaValue {
    /// The value as Python's `str()` writes it.
    pub fn python_str(&self) -> String {
        match self {
            MetaValue::Str(s) => s.clone(),
            MetaValue::Int(i) => i.to_string(),
            MetaValue::Bool(true) => "True".to_string(),
            MetaValue::Bool(false) => "False".to_string(),
            // Debug writes a float the way Python's repr does for ordinary values (1.0, 0.5).
            MetaValue::Float(f) => format!("{f:?}"),
        }
    }

    /// Python's truthiness: an empty string and a zero are false.
    pub fn truthy(&self) -> bool {
        match self {
            MetaValue::Str(s) => !s.is_empty(),
            MetaValue::Int(i) => *i != 0,
            MetaValue::Float(f) => *f != 0.0,
            MetaValue::Bool(b) => *b,
        }
    }
}

/// Why a match of a rule would make no detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionBlocker {
    /// `enabled` is falsy: the match is dropped as if it never matched.
    Disabled,
    /// `modifiers` includes `qa`.
    Qa,
    /// `modifiers` includes `no_alert`.
    NoAlert,
}

impl Meta {
    /// False only if the rule's `enabled` meta is set to a falsy value. True when it is absent.
    pub fn enabled(&self) -> bool {
        match self.get(META_ENABLED) {
            None => true,
            Some(MetaValue::Bool(b)) => *b,
            Some(MetaValue::Int(i)) => *i != 0,
            Some(MetaValue::Float(f)) => *f != 0.0,
            Some(MetaValue::Str(s)) => {
                !FALSE_META_VALUES.contains(&s.trim().to_lowercase().as_str())
            }
        }
    }

    /// The rule's `modifiers` meta as a list: comma separated, each entry trimmed, empty
    /// entries dropped. An absent `modifiers` is an empty list.
    pub fn modifiers(&self) -> Vec<String> {
        match self.get(META_MODIFIERS) {
            None => Vec::new(),
            Some(value) => value
                .python_str()
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }

    /// True when the rule runs in QA mode (`modifiers` includes `qa`).
    pub fn is_qa(&self) -> bool {
        self.modifiers().iter().any(|m| m == MODIFIER_QA)
    }

    /// True when `modifiers` includes `no_alert`.
    pub fn is_no_alert(&self) -> bool {
        self.modifiers().iter().any(|m| m == MODIFIER_NO_ALERT)
    }

    /// The rule's `uuid` meta, trimmed, or `None` when it is absent or falsy. A uuid that is
    /// only whitespace is `Some("")`, as in ace3.
    pub fn uuid(&self) -> Option<String> {
        self.get(META_UUID)
            .filter(|value| value.truthy())
            .map(|value| value.python_str().trim().to_string())
    }

    /// Why a match of this rule would make no detection, or `None` if it would make one: it
    /// is enabled and its modifiers include neither `qa` nor `no_alert`.
    pub fn detection_blocker(&self) -> Option<DetectionBlocker> {
        if !self.enabled() {
            return Some(DetectionBlocker::Disabled);
        }
        let modifiers = self.modifiers();
        if modifiers.iter().any(|m| m == MODIFIER_QA) {
            Some(DetectionBlocker::Qa)
        } else if modifiers.iter().any(|m| m == MODIFIER_NO_ALERT) {
            Some(DetectionBlocker::NoAlert)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    //! The cases in ace3's tests/saq/signatures/test_yara_meta.py, then the readings it
    //! doesn't test: no_alert, the uuid and the detection blocker. Python's `None` meta and
    //! `{}` are both an empty `Meta` here.

    use super::*;

    fn meta(pairs: &[(&str, MetaValue)]) -> Meta {
        Meta::from_pairs(pairs.iter().cloned())
    }

    fn s(value: &str) -> MetaValue {
        MetaValue::Str(value.to_string())
    }

    #[test]
    fn test_meta_enabled() {
        let cases = [
            (Meta::default(), true),
            (meta(&[("enabled", MetaValue::Bool(true))]), true),
            (meta(&[("enabled", MetaValue::Bool(false))]), false),
            (meta(&[("enabled", MetaValue::Int(0))]), false),
            (meta(&[("enabled", MetaValue::Int(1))]), true),
            (meta(&[("enabled", s("false"))]), false),
            (meta(&[("enabled", s(" Disabled "))]), false),
            (meta(&[("enabled", s("off"))]), false),
            (meta(&[("enabled", s("no"))]), false),
            (meta(&[("enabled", s("0"))]), false),
            (meta(&[("enabled", s("true"))]), true),
            (meta(&[("enabled", s("anything else"))]), true),
        ];
        for (meta, expected) in cases {
            assert_eq!(meta.enabled(), expected, "{meta:?}");
        }
    }

    #[test]
    fn test_meta_modifiers() {
        let cases: [(Meta, &[&str]); 4] = [
            (Meta::default(), &[]),
            (meta(&[("modifiers", s("qa"))]), &["qa"]),
            (
                meta(&[("modifiers", s(" no_alert , qa,, directive=sandbox "))]),
                &["no_alert", "qa", "directive=sandbox"],
            ),
            (meta(&[("modifiers", s(""))]), &[]),
        ];
        for (meta, expected) in cases {
            assert_eq!(meta.modifiers(), expected, "{meta:?}");
        }
    }

    #[test]
    fn test_meta_is_qa() {
        assert!(meta(&[("modifiers", s("no_alert,qa"))]).is_qa());
        assert!(!meta(&[("modifiers", s("no_alert"))]).is_qa());
        // a modifier that merely contains the letters is not qa mode
        assert!(!meta(&[("modifiers", s("qa_later"))]).is_qa());
        assert!(!Meta::default().is_qa());
    }

    #[test]
    fn no_alert() {
        assert!(meta(&[("modifiers", s("qa, no_alert"))]).is_no_alert());
        assert!(!meta(&[("modifiers", s("no_alert_later"))]).is_no_alert());
        assert!(!Meta::default().is_no_alert());
    }

    #[test]
    fn uuid_is_trimmed_and_none_when_absent_or_falsy() {
        assert_eq!(
            meta(&[("uuid", s(" 4c3c8330-545d-4673-9a7c-7bd4597d0098 "))]).uuid(),
            Some("4c3c8330-545d-4673-9a7c-7bd4597d0098".to_string())
        );
        assert_eq!(Meta::default().uuid(), None);
        assert_eq!(meta(&[("uuid", s(""))]).uuid(), None);
        assert_eq!(meta(&[("uuid", MetaValue::Int(0))]).uuid(), None);
        assert_eq!(
            meta(&[("uuid", MetaValue::Int(7))]).uuid(),
            Some("7".into())
        );
        assert_eq!(meta(&[("uuid", s("  "))]).uuid(), Some(String::new()));
    }

    #[test]
    fn a_match_makes_a_detection_unless_disabled_qa_or_no_alert() {
        assert_eq!(Meta::default().detection_blocker(), None);
        assert_eq!(
            meta(&[("modifiers", s("directive=sandbox"))]).detection_blocker(),
            None
        );
        assert_eq!(
            meta(&[("enabled", s("off")), ("modifiers", s("qa"))]).detection_blocker(),
            Some(DetectionBlocker::Disabled)
        );
        assert_eq!(
            meta(&[("modifiers", s("no_alert, qa"))]).detection_blocker(),
            Some(DetectionBlocker::Qa)
        );
        assert_eq!(
            meta(&[("modifiers", s("no_alert"))]).detection_blocker(),
            Some(DetectionBlocker::NoAlert)
        );
    }

    #[test]
    fn non_string_values_read_as_python_str_writes_them() {
        assert_eq!(
            meta(&[("modifiers", MetaValue::Bool(true))]).modifiers(),
            ["True"]
        );
        assert_eq!(meta(&[("modifiers", MetaValue::Int(5))]).modifiers(), ["5"]);
        assert_eq!(MetaValue::Float(1.0).python_str(), "1.0");
    }
}
