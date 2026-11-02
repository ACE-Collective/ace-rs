//! The record every result shares.
//!
//! A module's result is a `ResultEnvelope<D>`, where `D` is its analysis type's details. The core
//! reads results it hasn't a Rust type for, such as the Python pool's, as
//! `ResultEnvelope<serde_json::Value>`.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::file::NewFile;
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
    /// Tags this result puts on the observable it analyzed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
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
            observables: self.observables.clone(),
            files: self.files.clone(),
        })
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
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
        }
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
    use crate::file::{AlertPath, YaraMeta};
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
        };
        ResultEnvelope::new(HeaderDump {
            name: "Subject".to_owned(),
            // latin-1 "café" followed by an invalid UTF-8 sequence
            raw_value: Bytes::new(b"caf\xe9 \xff\xfe".to_vec()),
        })
        .with_summary("one header")
        .with_tag("suspect")
        .with_observable(NewObservable::new(
            ObservableKind::EmailFrom,
            "a@example.com",
        ))
        .with_file(file)
    }

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
                "observables": [{"type": "email_from", "value": "a@example.com"}],
                "files": [{
                    "path": "email.rfc822.headers",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "size": 0,
                    "yara_meta": ["type=email.headers"],
                    "exclude_modules": ["email_analyzer"],
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
