//! The record every result shares.
//!
//! A module's result is a `ResultEnvelope<D>`, where `D` is its analysis type's details. The core
//! reads results as `ResultEnvelope<serde_json::Value>`, since it has no Rust type for a site's.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::file::{NewFile, YaraMeta};
use crate::links::{Detection, ObservableRef, Relationship};
use crate::observable::ObservableKind;

/// An analysis type: the details one module writes, under a name and a schema version.
///
/// The name is what a result is stored and found by, never a code path. A change to the details
/// that old readers can't take bumps the version, and the old version's type stays so stored
/// results still read. Every struct in the details should carry `#[serde(deny_unknown_fields)]`,
/// so its schema refuses fields it doesn't declare.
pub trait AnalysisType: Serialize + DeserializeOwned + JsonSchema + 'static {
    /// The type's name, such as `email_analysis`.
    const NAME: &'static str;
    /// The schema version of the details, from 1.
    const VERSION: u32;
    /// The module that writes this type, so finding a type's module needs no instance of either
    /// (ace3 #827). Several configured instances of one module share its types.
    const MODULE: &'static str;
}

/// One module's result for one observable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultEnvelope<D> {
    analysis_type: String,
    schema_version: u32,
    /// The analysis type's own fields.
    pub details: D,
    /// One line for the alert view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Tags on the result itself, as ace3's analysis tags, such as `single_file_zip`. Tags for the
    /// observable the module analyzed go in `analyzed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Detection points on the result itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detections: Vec<Detection>,
    /// What the result adds to the observable the module analyzed.
    #[serde(default, skip_serializing_if = "ObservableAdditions::is_empty")]
    pub analyzed: ObservableAdditions,
    /// What the result adds to the observable the analyzed one redirects to, such as the Office
    /// document a part was extracted from: ace3's YARA module sandboxes that document rather than
    /// the part that matched.
    #[serde(default, skip_serializing_if = "ObservableAdditions::is_empty")]
    pub redirected: ObservableAdditions,
    /// Observables the result adds to the alert. Files go in `files` instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observables: Vec<NewObservable>,
    /// Files the result adds to the alert.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<NewFile>,
}

impl<D: AnalysisType> ResultEnvelope<D> {
    /// A result of `D`'s type and version, with nothing in it but the details.
    pub fn new(details: D) -> Self {
        ResultEnvelope {
            analysis_type: D::NAME.to_owned(),
            schema_version: D::VERSION,
            details,
            summary: None,
            tags: Vec::new(),
            detections: Vec::new(),
            analyzed: ObservableAdditions::default(),
            redirected: ObservableAdditions::default(),
            observables: Vec::new(),
            files: Vec::new(),
        }
    }

    /// Reads a result of `D`'s type, refusing one written for another type or version.
    pub fn from_json(value: serde_json::Value) -> Result<Self, EnvelopeError> {
        let envelope: Self = serde_json::from_value(value).map_err(EnvelopeError::Json)?;
        if envelope.analysis_type != D::NAME || envelope.schema_version != D::VERSION {
            return Err(EnvelopeError::WrongType {
                expected: (D::NAME, D::VERSION),
                found: (envelope.analysis_type, envelope.schema_version),
            });
        }
        Ok(envelope)
    }

    /// The same result with its details as JSON.
    pub fn to_raw(&self) -> Result<ResultEnvelope<serde_json::Value>, serde_json::Error> {
        Ok(ResultEnvelope {
            analysis_type: self.analysis_type.clone(),
            schema_version: self.schema_version,
            details: serde_json::to_value(&self.details)?,
            summary: self.summary.clone(),
            tags: self.tags.clone(),
            detections: self.detections.clone(),
            analyzed: self.analyzed.clone(),
            redirected: self.redirected.clone(),
            observables: self.observables.clone(),
            files: self.files.clone(),
        })
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Adds a tag to the result itself.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_detection(mut self, detection: Detection) -> Self {
        self.detections.push(detection);
        self
    }

    pub fn with_observable(mut self, observable: NewObservable) -> Self {
        self.observables.push(observable);
        self
    }

    pub fn with_file(mut self, file: NewFile) -> Self {
        self.files.push(file);
        self
    }
}

impl<D> ResultEnvelope<D> {
    pub fn analysis_type(&self) -> &str {
        &self.analysis_type
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// An observable a result adds to the alert. The alert keeps one observable per (type, value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewObservable {
    #[serde(rename = "type")]
    pub kind: ObservableKind,
    pub value: String,
    /// When the observable was seen, for kinds whose meaning depends on time, such as an IP
    /// address's owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directives: Vec<String>,
    /// Modules that must not analyze this observable, as ace3's `exclude_analysis`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detections: Vec<Detection>,
    /// Relationships from this observable to others, such as a file `extracted_from` the archive
    /// it came out of.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<Relationship>,
    /// The observable that stands for this one when something acts on it, as ace3's
    /// `redirection`: a part of an Office document redirects to the document, so a YARA match on
    /// the part sandboxes the document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirection: Option<ObservableRef>,
}

impl NewObservable {
    pub fn new(kind: ObservableKind, value: impl Into<String>) -> Self {
        NewObservable {
            kind,
            value: value.into(),
            time: None,
            tags: Vec::new(),
            directives: Vec::new(),
            exclude_modules: Vec::new(),
            detections: Vec::new(),
            relationships: Vec::new(),
            redirection: None,
        }
    }
}

/// What a result adds to an observable already in the alert: tags, directives, `yara_meta` tags
/// and detection points. ace3's modules change the observable they analyze this way, such as the
/// email module tagging a message `authentication_failed` or the YARA module adding `sandbox`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservableAdditions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directives: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub yara_meta: Vec<YaraMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detections: Vec<Detection>,
}

impl ObservableAdditions {
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
            && self.directives.is_empty()
            && self.yara_meta.is_empty()
            && self.detections.is_empty()
    }

    /// Adds a tag unless it is already there, as ace3's `add_tag` does.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        push_unique(&mut self.tags, tag.into());
    }

    /// Adds a directive unless it is already there, as ace3's `add_directive` does.
    pub fn add_directive(&mut self, directive: impl Into<String>) {
        push_unique(&mut self.directives, directive.into());
    }

    pub fn add_yara_meta(&mut self, tag: YaraMeta) {
        push_unique(&mut self.yara_meta, tag);
    }
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("invalid result: {0}")]
    Json(#[source] serde_json::Error),
    #[error(
        "expected a result of {} version {}, found {} version {}",
        expected.0, expected.1, found.0, found.1
    )]
    WrongType {
        expected: (&'static str, u32),
        found: (String, u32),
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::file::AlertPath;
    use crate::links::RelationshipKind;
    use serde_json::json;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct HeaderDump {
        name: String,
        raw_value: Bytes,
    }

    impl AnalysisType for HeaderDump {
        const NAME: &'static str = "header_dump";
        const VERSION: u32 = 1;
        const MODULE: &'static str = "header_dumper";
    }

    fn sample() -> ResultEnvelope<HeaderDump> {
        let file = NewFile {
            path: AlertPath::new("email.rfc822.headers").expect("valid path"),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .expect("valid sha256"),
            size: 0,
            yara_meta: vec![YaraMeta::new("type", "email.headers").expect("valid tag")],
            tags: vec![],
            directives: vec![],
            exclude_modules: vec!["email_analyzer".to_owned()],
            detections: vec![],
            relationships: vec![Relationship::new(
                RelationshipKind::ExtractedFrom,
                ObservableRef::new(ObservableKind::File, EMAIL_SHA256),
            )],
            redirection: Some(ObservableRef::new(ObservableKind::File, EMAIL_SHA256)),
        };
        let mut sender = NewObservable::new(ObservableKind::EmailFrom, "a@example.com");
        sender
            .detections
            .push(Detection::new("a known bad sender").with_signature("b3f6c7e2"));
        let mut result = ResultEnvelope::new(HeaderDump {
            name: "Subject".to_owned(),
            // latin-1 "café" followed by an invalid UTF-8 sequence
            raw_value: Bytes::new(b"caf\xe9 \xff\xfe".to_vec()),
        })
        .with_summary("one header")
        .with_tag("suspect")
        .with_detection(Detection::new("the subject is a lure"))
        .with_observable(sender)
        .with_file(file);
        result.analyzed.add_tag("authentication_failed");
        result.analyzed.add_directive("sandbox");
        result.analyzed.add_directive("sandbox");
        result
            .analyzed
            .add_yara_meta(YaraMeta::new("type", "email").expect("valid tag"));
        result
    }

    const EMAIL_SHA256: &str = "5d2569cdbe088294e456effabcfd8362108468f12deaf6464f95bc5400f85874";

    #[test]
    fn non_utf8_details_round_trip_through_json() {
        let original = sample();
        let text = serde_json::to_string(&original).expect("serializes");
        let back = ResultEnvelope::<HeaderDump>::from_json(
            serde_json::from_str(&text).expect("the output is JSON"),
        )
        .expect("reads back");
        assert_eq!(back, original);
        assert_eq!(back.details.raw_value.as_slice(), b"caf\xe9 \xff\xfe");
    }

    #[test]
    fn json_shape() {
        let value = serde_json::to_value(sample()).expect("serializes");
        assert_eq!(
            value,
            json!({
                "analysis_type": "header_dump",
                "schema_version": 1,
                "details": {"name": "Subject", "raw_value": {"base64": "Y2Fm6SD//g=="}},
                "summary": "one header",
                "tags": ["suspect"],
                "detections": [{"description": "the subject is a lure"}],
                "analyzed": {
                    "tags": ["authentication_failed"],
                    "directives": ["sandbox"],
                    "yara_meta": ["type=email"],
                },
                "observables": [{
                    "type": "email_from",
                    "value": "a@example.com",
                    "detections": [{
                        "description": "a known bad sender",
                        "signature_uuid": "b3f6c7e2",
                    }],
                }],
                "files": [{
                    "path": "email.rfc822.headers",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "size": 0,
                    "yara_meta": ["type=email.headers"],
                    "exclude_modules": ["email_analyzer"],
                    "relationships": [{
                        "type": "extracted_from",
                        "target": {"type": "file", "value": EMAIL_SHA256},
                    }],
                    "redirection": {"type": "file", "value": EMAIL_SHA256},
                }],
            })
        );
    }

    #[test]
    fn wrong_type_or_version_is_refused() {
        let mut value = serde_json::to_value(sample()).expect("serializes");
        value["schema_version"] = json!(2);
        let err = ResultEnvelope::<HeaderDump>::from_json(value).unwrap_err();
        assert!(
            matches!(err, EnvelopeError::WrongType { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut value = serde_json::to_value(sample()).expect("serializes");
        value["extra"] = json!(true);
        assert!(ResultEnvelope::<HeaderDump>::from_json(value).is_err());
    }

    #[test]
    fn raw_form_keeps_everything() {
        let original = sample();
        let raw = original.to_raw().expect("details serialize");
        assert_eq!(raw.analysis_type(), "header_dump");
        assert_eq!(
            serde_json::to_value(&raw).expect("raw serializes"),
            serde_json::to_value(&original).expect("typed serializes")
        );
    }
}
