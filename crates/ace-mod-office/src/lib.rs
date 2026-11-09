//! ace3's Office container modules (PLAN.md 7.5 batch 5): `onenote_extraction`, `officeparser3`,
//! `office_xml_rel`, `xml_binary_analyzer`, `xml_plain_text_analyzer`, `extracted_ole_analyzer`,
//! `hidden_mime` and `active_mime`. They write the files inside OneNote, compound, Word 2003 XML,
//! MIME and ActiveMime files, the text of Office XML and the external links of its relationships,
//! with ace3's names and `yara_meta` types.
//!
//! XML is parsed as lxml's target parser parses it (`ace_lxml::target`), MIME by `ace-mod-oletools`'
//! port of Python's feed parser, and compound files by a port of officeparser3 itself, whose own
//! reading of a damaged file is what decides what it writes.

pub mod active_mime;
pub mod extracted_ole;
pub mod hidden_mime;
pub mod officeparser;
pub mod onenote;
mod output;
pub mod xml;

pub use active_mime::ActiveMimeAnalyzer;
pub use extracted_ole::ExtractedOleAnalyzer;
pub use hidden_mime::HiddenMimeAnalyzer;
pub use officeparser::OfficeParserAnalyzer;
pub use onenote::OneNoteAnalyzer;
pub use xml::{OfficeXmlRelAnalyzer, XmlBinaryAnalyzer, XmlPlainTextAnalyzer};

use ace_results::{ObservableKind, ObservableRef, Relationship, RelationshipKind};
use ace_sdk::InputFile;

/// ace3's root takes at most 500 file observables and 500 URLs (`maximum_observable_count`), which
/// ace4's core doesn't, so a module stops there: at 499 files, since the root holds the file the
/// module reads, as in ace3's dumps, where a module writes at most 499.
pub const MAX_FILES: usize = 499;
pub const MAX_URLS: usize = 500;
/// ace3's `NAME_MAX_BYTES`: a longer name fails to open, as on ace3's file system.
const NAME_MAX_BYTES: usize = 255;

const DIRECTIVE_SANDBOX: &str = "sandbox";
const DIRECTIVE_EXTRACT_URLS: &str = "extract_urls";
const DIRECTIVE_FORCE_DOWNLOAD: &str = "force_download";
const DIRECTIVE_ORIGINAL_EMAIL: &str = "original_email";

/// `saq.util.strings.format_item_list_for_summary`, with its 20 items.
fn item_list(items: &[String]) -> String {
    let mut result = items[..items.len().min(20)].join(", ");
    if items.len() > 20 {
        result.push_str(&format!(" + {} more", items.len() - 20));
    }
    result
}

/// The input file as an observable, for a relationship or a redirection.
fn source(file: &InputFile) -> ObservableRef {
    ObservableRef::new(ObservableKind::File, file.sha256.to_hex())
}

fn extracted_from(file: &InputFile) -> Relationship {
    Relationship::new(RelationshipKind::ExtractedFrom, source(file))
}

/// Whether a directory `<file>.<suffix>` beside the file can be made: `os.mkdir` fails on a name
/// past `NAME_MAX`, which ace3 logs.
fn dir_name_fits(file: &InputFile, suffix: &str) -> bool {
    file.name().len() + suffix.len() <= NAME_MAX_BYTES
}
