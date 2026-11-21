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
    /// Why the module failed, when it ran to its end and says it failed, as ace3's
    /// `Analysis.error`: a tool that exited with an error, a lookup that couldn't answer, a file it
    /// couldn't read. None for a module that didn't fail. Whatever else the result holds is kept
    /// and shown as a partial result. A failure needs a reason, so the core refuses a result
    /// whose `error` is blank. A task that never produced a result (a crash, a deadline, a
    /// `ModuleError`) is a failed task, not this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = r"\S"))]
    pub error: Option<String>,
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
    /// What the result adds to observables already in the alert besides the one it analyzed, as
    /// ace3's modules that walk the tree change what they find there, such as the lure module's
    /// `crawl` on the URL it picks. The core takes only what the module declares (`Module::ADDS_TO_OTHERS`), and
    /// leaves alone an observable the alert doesn't hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub others: Vec<OtherAdditions>,
    /// Observables the result adds to the alert. Files go in `files` instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observables: Vec<NewObservable>,
    /// Files the result adds to the alert.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<NewFile>,
    /// Files the result stores for its root without adding them, for a module that depends on its
    /// module to add (`Module::ADDS_STORED_FILES`), as ace3's pcap_analyzer writes the objects it
    /// carves beside the capture and pcap_files adds them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stored: Vec<StoredFile>,
    /// What the result changes about its root, for a module that declares it may, as ace3's
    /// mailbox module sets the root's description and details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<RootChanges>,
    /// Links out of ACE to where the result came from, such as a vendor's page about the email
    /// (ace3's `Analysis.pivot_links`, PLAN.md decision 32 part (b)), in order. The GUI shows each
    /// beside the result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 100))]
    pub pivot_links: Vec<PivotLink>,
}

/// The most pivot links one result, or one root, holds.
pub const MAX_PIVOT_LINKS: usize = 100;

/// A link out of ACE with a label and, if it has one, an icon: ace3's `PivotLink`. Only an
/// `https://` URL of printable ASCII with nothing an attribute or a browser would read differently
/// (no quote, angle bracket, backslash or backtick) is taken, so a link can't run script or break out
/// of the page. The icon is the name of an image the binary registers and ACE serves itself
/// (`ace_app::App::pivot_link_icon`); ace3 also takes a `data:` URL or another site's image, which
/// ace4 refuses, as its pages load images from ACE alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PivotLink {
    #[schemars(
        regex(pattern = r"^https://[!#-&(-;=?-\[\]-_a-~]+$"),
        length(max = 4096)
    )]
    pub url: String,
    /// What the link says, and the icon's alternative text.
    #[schemars(regex(pattern = r"\S"), length(max = 1024))]
    pub text: String,
    /// The registered icon's name: 1 to 64 of a-z, 0-9, `_` and `-`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = r"^[a-z0-9_-]{1,64}$"))]
    pub icon: Option<String>,
}

impl PivotLink {
    /// A link with a label and no icon.
    pub fn new(url: impl Into<String>, text: impl Into<String>) -> PivotLink {
        PivotLink {
            url: url.into(),
            text: text.into(),
            icon: None,
        }
    }

    /// The link with the registered icon `name`.
    pub fn with_icon(mut self, name: impl Into<String>) -> PivotLink {
        self.icon = Some(name.into());
        self
    }

    /// Why the link can't be taken, if it can't: the same rules as its schema, for links that come
    /// from elsewhere than a result, such as a hunt's.
    pub fn refusal(&self) -> Option<String> {
        let plain = |text: &str| {
            text.bytes().all(|b| b.is_ascii_graphic())
                && !text.contains(['"', '\'', '<', '>', '\\', '`'])
        };
        if self.url.len() > 4096
            || !self.url.starts_with("https://")
            || self.url.len() == "https://".len()
            || !plain(&self.url)
        {
            return Some(format!("{:?} isn't a plain https:// URL", self.url));
        }
        if self.text.trim().is_empty() || self.text.chars().count() > 1024 {
            return Some("a link needs a label of at most 1,024 characters".to_owned());
        }
        if let Some(icon) = &self.icon
            && !is_icon_name(icon)
        {
            return Some(format!(
                "{icon:?} isn't an icon's name: 1 to 64 of a-z, 0-9, _ and -"
            ));
        }
        None
    }
}

/// An icon's name: 1 to 64 of a-z, 0-9, `_` and `-`.
pub fn is_icon_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A file a result stores for its root without adding it (`ResultEnvelope::stored`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoredFile {
    pub sha256: crate::file::Sha256,
    pub size: u64,
}

impl From<&NewFile> for StoredFile {
    fn from(file: &NewFile) -> StoredFile {
        StoredFile {
            sha256: file.sha256,
            size: file.size,
        }
    }
}

/// What a result adds to an observable already in the alert that it didn't analyze.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OtherAdditions {
    pub observable: ObservableRef,
    pub additions: ObservableAdditions,
}

/// What a result changes about its root.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootChanges {
    /// The root's new description, in place of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Keys merged into the root's details, each in place of one of the same name, as Python's
    /// `dict.update`. The root's details are the `details` its submitter gave, if it gave any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Map<String, serde_json::Value>>,
}

impl<D: AnalysisType> ResultEnvelope<D> {
    /// A result of `D`'s type and version, with nothing in it but the details.
    pub fn new(details: D) -> Self {
        ResultEnvelope {
            analysis_type: D::NAME.to_owned(),
            schema_version: D::VERSION,
            details,
            summary: None,
            error: None,
            tags: Vec::new(),
            detections: Vec::new(),
            analyzed: ObservableAdditions::default(),
            redirected: ObservableAdditions::default(),
            others: Vec::new(),
            observables: Vec::new(),
            files: Vec::new(),
            stored: Vec::new(),
            root: None,
            pivot_links: Vec::new(),
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
            error: self.error.clone(),
            tags: self.tags.clone(),
            detections: self.detections.clone(),
            analyzed: self.analyzed.clone(),
            redirected: self.redirected.clone(),
            others: self.others.clone(),
            observables: self.observables.clone(),
            files: self.files.clone(),
            stored: self.stored.clone(),
            root: self.root.clone(),
            pivot_links: self.pivot_links.clone(),
        })
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Adds a link out of ACE beside the result (`ResultEnvelope::pivot_links`).
    pub fn with_pivot_link(mut self, link: PivotLink) -> Self {
        self.pivot_links.push(link);
        self
    }

    /// Marks the result failed, with the reason (`ResultEnvelope::error`).
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
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
    /// The label the alert view shows in place of the type's name, such as `Source IP`, as ace3's
    /// `display_type`, which an observable mapping or a module sets. The alert keeps one per
    /// observable: a later result's label replaces an earlier one, and a result without one leaves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_type: Option<String>,
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
            display_type: None,
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
            role: Some(crate::FileRole::EMAIL_HEADERS),
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
                    "role": "email.headers",
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
    fn a_failed_result_carries_its_reason() {
        let failed = sample().with_error("the tool exited with status 2");
        let value = serde_json::to_value(&failed).expect("serializes");
        assert_eq!(value["error"], json!("the tool exited with status 2"));
        // and keeps what it had: a failure is a partial result, not an empty one
        assert_eq!(value["summary"], json!("one header"));
        let back = ResultEnvelope::<HeaderDump>::from_json(value).expect("reads back");
        assert_eq!(back, failed);
        assert_eq!(
            back.to_raw().expect("details serialize").error.as_deref(),
            Some("the tool exited with status 2")
        );
        // a result that didn't fail has no such key, so results stored before the mark still read
        assert!(
            serde_json::to_value(sample())
                .expect("serializes")
                .get("error")
                .is_none()
        );
    }

    /// PLAN.md decision 32 part (b): a pivot link is an `https://` URL of plain characters with a
    /// label and, if any, a registered icon's name; the schema and `PivotLink::refusal` refuse the
    /// same links, a `data:` icon and another site's image among them.
    #[test]
    fn a_pivot_link_is_a_plain_https_link_with_a_named_icon() {
        let validator = crate::validate::ResultValidator::of::<HeaderDump>().expect("a schema");
        let good = PivotLink::new(
            "https://portal.example.com/messages/1?id=a%20b&x=#top",
            "Example Portal",
        )
        .with_icon("example_portal");
        assert_eq!(good.refusal(), None);
        let value = serde_json::to_value(sample().with_pivot_link(good.clone())).expect("json");
        validator.validate(&value).expect("a plain link passes");
        assert_eq!(value["pivot_links"][0]["icon"], "example_portal");
        let bad = [
            PivotLink::new("http://portal.example.com/", "plain http"),
            PivotLink::new("javascript:alert(1)", "script"),
            PivotLink::new("https://", "no host"),
            PivotLink::new("https://example.com/\"onmouseover=\"x", "a quote"),
            PivotLink::new("https://example.com/<b>", "angle brackets"),
            PivotLink::new("https://example.com/a b", "a space"),
            PivotLink::new("https://example.com/", "  "),
            good.clone().with_icon("data:image/png;base64,iVBORw0KGgo="),
            good.clone().with_icon("https://cdn.example.com/icon.png"),
            good.clone().with_icon("Upper"),
        ];
        for link in bad {
            assert!(link.refusal().is_some(), "{link:?}");
            let value = serde_json::to_value(sample().with_pivot_link(link.clone())).expect("json");
            assert!(validator.validate(&value).is_err(), "{link:?}");
        }
        let many = (0..=MAX_PIVOT_LINKS).fold(sample(), |r, _| r.with_pivot_link(good.clone()));
        assert!(
            validator
                .validate(&serde_json::to_value(many).expect("json"))
                .is_err()
        );
        // a result without links says nothing about them
        let plain = serde_json::to_value(sample()).expect("json");
        assert!(plain.get("pivot_links").is_none());
    }

    #[test]
    fn a_failure_needs_a_reason() {
        let validator = crate::validate::ResultValidator::of::<HeaderDump>().expect("a schema");
        for blank in ["", "  ", "\n\t"] {
            let value = serde_json::to_value(sample().with_error(blank)).expect("serializes");
            let invalid = validator
                .validate(&value)
                .expect_err("a blank reason is refused");
            assert_eq!(invalid.fields()[0].path, "/error", "{blank:?}");
        }
        let value = serde_json::to_value(sample().with_error("x")).expect("serializes");
        validator.validate(&value).expect("a reason passes");
        validator
            .validate(&serde_json::to_value(sample()).expect("serializes"))
            .expect("no failure passes");
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
