//! What a result says about observables beyond adding them: detection points, relationships
//! between observables, and redirection.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::observable::ObservableKind;

/// An observable already in the alert, or added by the same result, named by its type and
/// value. A file's value is its sha256 in hex.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ObservableRef {
    #[serde(rename = "type")]
    pub kind: ObservableKind,
    pub value: String,
}

impl ObservableRef {
    pub fn new(kind: ObservableKind, value: impl Into<String>) -> Self {
        ObservableRef {
            kind,
            value: value.into(),
        }
    }
}

/// A detection point: something seen that makes the alert worth an analyst's time, as ace3's
/// `DetectionPoint`. It sits on a result or on an observable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    pub description: String,
    /// Structured facts about the detection, such as the rule a YARA match came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// The alert queue the detection asks for, as a YARA rule's `queue` meta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// The signature that raised it, such as a YARA rule's `uuid` meta or one of ace3's built-in
    /// signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_uuid: Option<String>,
    /// The signature's version, such as the commit of the rule's repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_version: Option<String>,
    /// The kind of signature, such as `yara`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_family: Option<String>,
}

impl Detection {
    pub fn new(description: impl Into<String>) -> Self {
        Detection {
            description: description.into(),
            details: None,
            queue: None,
            signature_uuid: None,
            signature_version: None,
            signature_family: None,
        }
    }

    pub fn with_signature(mut self, uuid: impl Into<String>) -> Self {
        self.signature_uuid = Some(uuid.into());
        self
    }
}

/// How one observable relates to another, as ace3's `R_*` relationship types.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    RelatedTo,
    DownloadedFrom,
    ExecutedOn,
    /// A file taken out of another file, such as an archive member.
    ExtractedFrom,
    IsHashOf,
    LoggedInto,
    RedirectedFrom,
}

/// A relationship from the observable that carries it to `target`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    #[serde(rename = "type")]
    pub kind: RelationshipKind,
    pub target: ObservableRef,
}

impl Relationship {
    pub fn new(kind: RelationshipKind, target: ObservableRef) -> Self {
        Relationship { kind, target }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn relationship_kinds_use_ace3_names() {
        let kinds = [
            (RelationshipKind::RelatedTo, "related_to"),
            (RelationshipKind::DownloadedFrom, "downloaded_from"),
            (RelationshipKind::ExecutedOn, "executed_on"),
            (RelationshipKind::ExtractedFrom, "extracted_from"),
            (RelationshipKind::IsHashOf, "is_hash_of"),
            (RelationshipKind::LoggedInto, "logged_into"),
            (RelationshipKind::RedirectedFrom, "redirected_from"),
        ];
        for (kind, name) in kinds {
            assert_eq!(serde_json::to_value(kind).expect("serializes"), json!(name));
        }
    }

    #[test]
    fn a_detection_with_only_a_description_is_one_field() {
        assert_eq!(
            serde_json::to_value(Detection::new("bad")).expect("serializes"),
            json!({"description": "bad"})
        );
    }
}
