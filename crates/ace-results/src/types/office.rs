//! The results of PLAN.md 7.5 batch 5's Office container modules, which `ace-mod-office` writes:
//! ace3's `OneNoteFileAnalysis` (`saq/modules/file_analysis/one_note.py`), `OfficeParserAnalysis3`
//! (`officeparser3.py`), `OfficeXMLRelationshipExternalURLAnalysis` (`msoffice.py`),
//! `XMLBinaryDataAnalysis` and `XMLPlainTextAnalysis` (`xml.py`), `ExtractedOLEAnalysis`
//! (`ole.py`), and `HiddenMIMEAnalysis` and `ActiveMimeAnalysis` (`mime.py`), with ace3's keys.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `onenote_file_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OneNoteFileAnalysis {
    /// The sha256 of each embedded file written out, in the order found, a file found twice twice.
    pub extracted_files: Vec<String>,
}

impl AnalysisType for OneNoteFileAnalysis {
    const NAME: &'static str = "onenote_file_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "onenote_extraction";
}

/// The details of an `officeparser_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeParserAnalysis {
    /// The names in officeparser3's manifest of the files added, in its order: streams
    /// (`stream_<index>_<n>.dat`), embedded packages by their own names, macros and the bytes past
    /// the FAT (`unknown_sectors_<n>.dat`).
    pub extracted_files: Vec<String>,
}

impl AnalysisType for OfficeParserAnalysis {
    const NAME: &'static str = "officeparser_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "officeparser3";
}

/// The details of an `office_xml_relationship_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfficeXmlRelationshipAnalysis {
    /// The target of each external `oleObject` relationship, in document order, whether or not it
    /// is a URL.
    pub urls: Vec<String>,
}

impl AnalysisType for OfficeXmlRelationshipAnalysis {
    const NAME: &'static str = "office_xml_relationship_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "office_xml_rel";
}

/// The details of an `xml_binary_data_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XmlBinaryDataAnalysis {
    /// Each part written out, as ace3 names it: `files/` and its path in the alert.
    pub extracted_files: Vec<String>,
}

impl AnalysisType for XmlBinaryDataAnalysis {
    const NAME: &'static str = "xml_binary_data_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "xml_binary_analyzer";
}

/// The details of an `xml_plain_text_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XmlPlainTextAnalysis {
    /// The `.noxml` file's path in the alert, or null when the document has no text or doesn't
    /// parse.
    pub xml_plain_text: Option<String>,
}

impl AnalysisType for XmlPlainTextAnalysis {
    const NAME: &'static str = "xml_plain_text_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "xml_plain_text_analyzer";
}

/// The details of an `extracted_ole_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractedOleAnalysis {
    /// The file's path in the alert when it is suspect: by its type, its extension, or because it
    /// parses as JavaScript.
    pub suspect_files: Vec<String>,
}

impl AnalysisType for ExtractedOleAnalysis {
    const NAME: &'static str = "extracted_ole_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "extracted_ole_analyzer";
}

/// The details of a `hidden_mime_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HiddenMimeAnalysis {
    /// Each part written out, by its path in the alert.
    pub extracted_files: Vec<String>,
}

impl AnalysisType for HiddenMimeAnalysis {
    const NAME: &'static str = "hidden_mime_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "hidden_mime";
}

/// The details of an `active_mime_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveMimeAnalysis {
    /// The decompressed payload's path in the alert.
    pub extracted_file: String,
}

impl AnalysisType for ActiveMimeAnalysis {
    const NAME: &'static str = "active_mime_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "active_mime";
}
