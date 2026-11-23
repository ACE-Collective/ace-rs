//! ace3's three modules that read Office XML with lxml's target parser:
//!
//! - `office_xml_rel`, `OfficeXMLRelationshipExternalURLAnalyzer` (`msoffice.py`): a file named
//!   `document.xml.rels` gives the `Target` of each `Relationship` whose `Type` ends `/oleObject`
//!   and whose `TargetMode` is `External`, as a URL with `force_download`, and a detection on the
//!   file. What was found before a parse error is kept.
//! - `xml_binary_analyzer`, `XMLBinaryDataAnalyzer` (`xml.py`): a Word 2003 XML package, `<?xml`
//!   (the type's `has_xml_marker`) and `Word.Document` in its first KiB, has each named part's `binaryData` base64-decoded into
//!   `<file>.xml/<part name>`, the name cleaned and numbered as ace3's `create_output_file` does. A
//!   parse error keeps none of them.
//! - `xml_plain_text_analyzer`, `XMLPlainTextAnalyzer` (`xml.py`): an XML file of at most
//!   `maximum_size` bytes, extracted from a file tagged `microsoft_office`, has its text and the
//!   values of attributes whose names hold `instr` written to `<file>.noxml`.
//!
//! The parser is `ace_lxml::target`, libxml2 as lxml 6.1.3 drives it.
//!
//! Where ace-rs departs:
//!
//! - `xml_plain_text_analyzer` reads the tags of the file its file was extracted from, which the
//!   core gives it as they are when the task is leased. The modules that extract Office parts, the
//!   archive module above all, wait for file_type as ace3's do, so file_type has tagged that file
//!   by then, as ace3 has a pass before. A module that extracts XML without waiting for file_type
//!   could be read before the tag lands. ace3 takes the first `extracted_from` relationship the
//!   file got; ace-rs has them in the order of their targets.
//! - `xml_binary_analyzer` sees only its own input and outputs when it numbers a name, where ace3
//!   sees the whole alert's directory.
//! - An XML file in an encoding libxml2 doesn't decode itself, such as windows-1252, is refused
//!   here, where lxml's libxml2 has iconv.
//! - Each module writes at most 499 files, and `office_xml_rel` adds at most 500 URLs: ace3's root
//!   takes 500 of each, and holds the file itself.

use std::collections::BTreeSet;

use ace_lxml::target::{Target, XmlSyntaxError, parse};
use ace_mod_email::naming::clean_file_name;
use ace_mod_urls::url_extraction::names_a_host;
use ace_results::types::office::{
    OfficeXmlRelationshipAnalysis, XmlBinaryDataAnalysis, XmlPlainTextAnalysis,
};
use ace_results::{
    AnalysisType, Detection, NewObservable, ObservableKind, RelationshipKind, ResultEnvelope,
};
use ace_sdk::takes::{Case, Condition, Takes, Text, TypeFact};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::output::OutputFiles;
use crate::{DIRECTIVE_FORCE_DOWNLOAD, MAX_FILES, MAX_URLS, item_list};

pub const OFFICE_XML_REL_MANIFEST: Manifest = Manifest::parser::<OfficeXmlRelAnalyzer>();
pub const XML_BINARY_MANIFEST: Manifest = Manifest::parser::<XmlBinaryAnalyzer>();
pub const XML_PLAIN_TEXT_MANIFEST: Manifest = Manifest::parser::<XmlPlainTextAnalyzer>();

/// ace3's built-in `OFFICE_EXTERNAL_OLEOBJECT` signature.
const OFFICE_EXTERNAL_OLEOBJECT: &str = "6ee4fb89-87d9-4cf0-85ec-52f7760b9a1d";

fn head(data: &[u8]) -> &[u8] {
    &data[..data.len().min(1024)]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

// ---- office_xml_rel ----

/// `_xml_parser`.
#[derive(Default)]
struct Relationships {
    urls: Vec<String>,
}

impl Target for Relationships {
    fn start(&mut self, tag: &str, attrib: &[(String, String)]) {
        if !tag.ends_with("Relationship") {
            return;
        }
        let get = |name: &str| attrib.iter().find(|(n, _)| n == name).map(|(_, v)| v);
        let (Some(kind), Some(mode), Some(target)) =
            (get("Type"), get("TargetMode"), get("Target"))
        else {
            return;
        };
        if kind.ends_with("/oleObject") && mode == "External" {
            self.urls.push(target.clone());
        }
    }
    fn end(&mut self, _: &str) {}
    fn data(&mut self, _: &str) {}
}

/// The external `oleObject` targets of a relationships part, and what lxml raised when it didn't
/// parse; the targets read before the error are kept.
pub fn external_ole_objects(data: &[u8]) -> (Vec<String>, Option<XmlSyntaxError>) {
    let mut target = Relationships::default();
    let raised = parse(data, &mut target).err();
    (target.urls, raised)
}

/// `generate_summary`: the targets' hosts, sorted.
fn relationship_summary(urls: &[String]) -> Option<String> {
    if urls.is_empty() {
        return None;
    }
    let domains: BTreeSet<String> = urls
        .iter()
        .filter_map(|url| ace_pycompat::parse::urlparse(url, "", true).ok())
        .filter_map(|parsed| parsed.hostname())
        .filter(|host| !host.is_empty())
        .collect();
    let domains: Vec<String> = domains.into_iter().collect();
    Some(format!("Office XML URL Analysis: {}", item_list(&domains)))
}

pub struct OfficeXmlRelAnalyzer;

impl Module for OfficeXmlRelAnalyzer {
    const NAME: &'static str = OfficeXmlRelationshipAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = OfficeXmlRelationshipAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(OfficeXmlRelAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        Takes::everything().and(
            Condition::Name(Text::equals("document.xml.rels")),
            "not document.xml.rels",
        )
    }
}

impl Parser for OfficeXmlRelAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<OfficeXmlRelationshipAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = std::fs::read(&file.local_path)?;
        let (urls, raised) = external_ole_objects(&data);
        let summary = relationship_summary(&urls);
        let mut result = ResultEnvelope::new(OfficeXmlRelationshipAnalysis { urls: urls.clone() });
        result.summary = summary;
        if let Some(raised) = raised {
            // the targets read before the error are still added
            let error = format!(
                "unable to parse {}: {}",
                file.name(),
                raised.python_str(file.name())
            );
            tracing::warn!("{error}");
            result.error = Some(error);
        }
        for url in &urls {
            // a target that isn't a URL adds no observable, but the external link still alerts
            // ace3's root takes no more URLs
            if result.observables.len() < MAX_URLS && !url.is_empty() && names_a_host(url) {
                let mut observable = NewObservable::new(ObservableKind::Url, url.clone());
                observable
                    .directives
                    .push(DIRECTIVE_FORCE_DOWNLOAD.to_owned());
                if !result.observables.contains(&observable) {
                    result.observables.push(observable);
                }
            }
        }
        if !urls.is_empty() {
            // one, however many: ace3 keeps one detection point per description
            result.analyzed.detections.push(
                Detection::new(format!(
                    "{} contains a link to an external oleobject",
                    file.path
                ))
                .with_signature(OFFICE_EXTERNAL_OLEOBJECT),
            );
        }
        Ok(Outcome::Done(result))
    }
}

// ---- xml_binary_analyzer ----

const PART_TAG: &str = "{http://schemas.microsoft.com/office/2006/xmlPackage}part";
const PART_NAME: &str = "{http://schemas.microsoft.com/office/2006/xmlPackage}name";
const DATA_TAG: &str = "{http://schemas.microsoft.com/office/2006/xmlPackage}binaryData";

/// `_XMLParser`: each part's name, as ace3's `create_output_file` names its file, and its bytes.
/// A part whose base64 doesn't decode still takes its name, as ace3 creates the file first.
struct Package<'o> {
    output_dir: String,
    names: &'o mut OutputFiles,
    part_name: Option<String>,
    data: Vec<String>,
    extracted: Vec<(String, Vec<u8>)>,
}

impl Target for Package<'_> {
    fn start(&mut self, tag: &str, attrib: &[(String, String)]) {
        if tag == PART_TAG {
            self.part_name = attrib
                .iter()
                .find(|(n, _)| n == PART_NAME)
                .map(|(_, v)| v.clone());
        }
        if tag == DATA_TAG {
            self.data.clear();
        }
    }

    fn end(&mut self, tag: &str) {
        let named = self.part_name.as_deref().is_some_and(|n| !n.is_empty());
        if tag != DATA_TAG || !named || self.data.is_empty() {
            return;
        }
        let part_name = self.part_name.take().unwrap_or_default();
        let path = self.names.create(&format!(
            "{}/{}",
            self.output_dir,
            clean_file_name(&part_name)
        ));
        match ace_pycompat::base64::b64decode(&self.data.concat()) {
            Ok(bytes) => self.extracted.push((path, bytes)),
            Err(e) => tracing::error!("unable to extract base64 encoded data: {e}"),
        }
        self.data.clear();
    }

    fn data(&mut self, text: &str) {
        if self.part_name.as_deref().is_some_and(|n| !n.is_empty()) {
            self.data.push(text.to_owned());
        }
    }
}

/// The parts of a Word 2003 XML package at `path`, with their paths in the alert, or what lxml
/// raised when the parse did.
pub fn package_parts(path: &str, data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, XmlSyntaxError> {
    let mut names = OutputFiles::new(path);
    let mut package = Package {
        output_dir: format!("{path}.xml"),
        names: &mut names,
        part_name: None,
        data: Vec::new(),
        extracted: Vec::new(),
    };
    parse(data, &mut package)?;
    Ok(package.extracted)
}

pub struct XmlBinaryAnalyzer;

impl Module for XmlBinaryAnalyzer {
    const NAME: &'static str = XmlBinaryDataAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = XmlBinaryDataAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(XmlBinaryAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        // `<?xml` in the first KiB, which the type step tests (PLAN.md decision 25)
        Takes::everything().and(
            Condition::type_fact(TypeFact::HasXmlMarker),
            "not an XML document",
        )
    }
}

impl Parser for XmlBinaryAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<XmlBinaryDataAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = std::fs::read(&file.local_path)?;
        if !contains(head(&data), b"Word.Document") {
            return Ok(Outcome::Skipped("not a Word.Document".to_owned()));
        }
        let mut analysis = XmlBinaryDataAnalysis::default();
        let mut files = Vec::new();
        let mut error = None;
        match package_parts(file.path.as_str(), &data) {
            Err(raised) => {
                let reason = format!("unable to parse XML: {}", raised.python_str(file.name()));
                tracing::info!("{reason}");
                error = Some(reason);
            }
            Ok(parts) => {
                for (path, bytes) in parts.into_iter().take(MAX_FILES) {
                    ctx.check_cancelled()?;
                    files.push(ctx.write_file(&path, &bytes, None)?);
                    analysis.extracted_files.push(format!("files/{path}"));
                }
            }
        }
        let summary = (!analysis.extracted_files.is_empty()).then(|| {
            format!(
                "XML Binary Data Analysis: extracted {}",
                item_list(&analysis.extracted_files)
            )
        });
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        result.error = error;
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

// ---- xml_plain_text_analyzer ----

/// `_XMLPlainTextDumper`: what it appends to the `.noxml` file.
#[derive(Default)]
struct PlainText {
    out: String,
    data: Vec<String>,
}

impl Target for PlainText {
    fn start(&mut self, _: &str, attrib: &[(String, String)]) {
        for (name, value) in attrib {
            if name.contains("instr") {
                self.out.push_str(value);
            }
        }
    }
    fn end(&mut self, _: &str) {
        for text in self.data.drain(..) {
            self.out.push_str(&text);
        }
    }
    fn data(&mut self, text: &str) {
        self.data.push(text.to_owned());
    }
}

/// The text the dumper writes for an XML document, or what lxml raised when the parse did.
pub fn plain_text(data: &[u8]) -> Result<String, XmlSyntaxError> {
    let mut dumper = PlainText::default();
    parse(data, &mut dumper)?;
    Ok(dumper.out)
}

/// ace3's settings of the module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct XmlPlainTextSettings {
    /// The largest file analyzed, in bytes.
    pub maximum_size: u64,
}

impl Default for XmlPlainTextSettings {
    fn default() -> Self {
        XmlPlainTextSettings {
            maximum_size: 131_072,
        }
    }
}

pub struct XmlPlainTextAnalyzer;

impl Module for XmlPlainTextAnalyzer {
    const NAME: &'static str = XmlPlainTextAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const READS_RELATED_TAGS: bool = true;
    type Output = XmlPlainTextAnalysis;
    type Settings = XmlPlainTextSettings;

    fn init(_: &XmlPlainTextSettings) -> Result<Self, ModuleError> {
        Ok(XmlPlainTextAnalyzer)
    }

    fn takes(settings: &XmlPlainTextSettings) -> Takes {
        Takes::everything()
            .and(
                Condition::Name(Text::ends_with(".noxml", Case::Exact)).negated(),
                "a .noxml file",
            )
            .and(Condition::at_most(settings.maximum_size), "too large")
            .and(
                Condition::type_fact(TypeFact::HasXmlMarker),
                "not an XML document",
            )
            .and(
                Condition::Relationship(RelationshipKind::ExtractedFrom),
                "not extracted from anything",
            )
    }
}

impl Parser for XmlPlainTextAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<XmlPlainTextSettings>,
    ) -> Result<Outcome<XmlPlainTextAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = std::fs::read(&file.local_path)?;
        // `takes` declined a file without one
        let Some(source) = ctx
            .observable()
            .relationship(RelationshipKind::ExtractedFrom)
        else {
            return Ok(Outcome::Skipped("not extracted from anything".to_owned()));
        };
        let office = ctx
            .related_tags(&source.target)
            .is_some_and(|tags| tags.iter().any(|t| t == "microsoft_office"));
        if !office {
            return Ok(Outcome::Skipped(
                "not extracted from a microsoft_office file".to_owned(),
            ));
        }
        let mut analysis = XmlPlainTextAnalysis::default();
        let mut files = Vec::new();
        let mut error = None;
        match plain_text(&data) {
            Err(raised) => {
                let reason = format!("unable to parse XML: {}", raised.python_str(file.name()));
                tracing::info!("{reason}");
                error = Some(reason);
            }
            Ok(text) if text.is_empty() => {}
            Ok(text) => {
                let path = format!("{}.noxml", file.path);
                files.push(ctx.write_file(&path, text.as_bytes(), None)?);
                analysis.xml_plain_text = Some(path);
            }
        }
        let mut result = ResultEnvelope::new(analysis);
        result.error = error;
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationships_are_external_ole_objects() {
        let rels = br#"<?xml version="1.0"?><Relationships xmlns="urn:r"><Relationship Type="x/oleObject" TargetMode="External" Target="http://a/"/><Relationship Type="x/oleObject" Target="b"/><Relationship Type="x/image" TargetMode="External" Target="c"/></Relationships>"#;
        assert_eq!(
            external_ole_objects(rels),
            (vec!["http://a/".to_owned()], None)
        );
        // the targets read before the error are kept, and the error is lxml's
        let (urls, raised) = external_ole_objects(
            b"<r><Relationship Type='/oleObject' TargetMode='External' Target='x'/><oops></r>",
        );
        assert_eq!(urls, ["x"]);
        assert_eq!(
            raised
                .expect("the parse raised")
                .python_str("word/_rels/document.xml.rels"),
            "Opening and ending tag mismatch: oops line 1 and r, line 1, column 80 \
             (document.xml.rels, line 1)"
        );
    }

    #[test]
    fn plain_text_is_text_and_instr_attributes() {
        let text = plain_text(br#"<?xml version="1.0"?><r xmlns:i="urn:instructions"><a i:x="1" instrument="2" no="3">t<b>u</b>v</a>w</r>"#);
        assert_eq!(text.as_deref(), Ok("12tuvw"));
        assert!(plain_text(b"<r><a>t</b></r>").is_err());
    }

    #[test]
    fn package_parts_are_named_as_ace3_names_them() {
        let doc = r#"<?xml version="1.0"?><pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage"><pkg:part pkg:name="/a/b.bin"><pkg:binaryData>QUJD</pkg:binaryData></pkg:part><pkg:part pkg:name="/a/b.bin"><pkg:binaryData>QQ</pkg:binaryData></pkg:part><pkg:part pkg:name="/a/b.bin"><pkg:binaryData>REVG</pkg:binaryData></pkg:part></pkg:package>"#;
        let parts = package_parts("x.xml", doc.as_bytes()).unwrap();
        assert_eq!(
            parts,
            vec![
                ("x.xml.xml/a/b.bin".to_owned(), b"ABC".to_vec()),
                ("x.xml.xml/a/b_001.bin".to_owned(), b"DEF".to_vec()),
            ]
        );
    }
}
