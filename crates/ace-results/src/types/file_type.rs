//! A file's type: what its bytes are (docs/decisions/0003, PLAN.md decision 25).
//!
//! `TypeFacts` is what the type step, `ace-mod-files`' `file_type`, finds in a file's bytes:
//! libmagic's description and mime type, the checks of ace3's `is_file_type.py` that read only the
//! bytes, and the first-byte tests of the modules that read the type to decide whether to act (a
//! packet capture, OneNote's header, a Java class, `<?xml`, EPS, an encoded script, a HAR). The
//! core keeps them once per sha256 (`store.file_types`); they are not a result in the tree.
//!
//! `FileTypeAnalysis` is ace3's `file_type_analysis` result (`saq/modules/file_analysis/file_type.py`),
//! which ace4 no longer stores. It is built from a file's facts and the path it is analyzed under
//! (`FileTypeAnalysis::from_facts`), because two of its checks read the name as well as the bytes,
//! for what still reads it: the comparison's normal form, the modules ace3 makes depend on
//! `file_type`, and the hooks' tree conditions. `TypeFacts::view` gives the tags and `yara_meta`
//! types ace3's module gave the file, from the same facts and path.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `file_type_analysis` result, with ace3's keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileTypeAnalysis {
    /// libmagic's description of the file, as `file -b -L` prints it, stripped.
    #[serde(rename = "type")]
    pub file_type: String,
    /// libmagic's mime type, as `file -b --mime-type -L` prints it.
    pub mime: String,
    /// The name ends in an extension Office opens.
    pub is_office_ext: bool,
    /// The file starts with the OLE compound file signature.
    pub is_ole_file: bool,
    /// The file starts with `\rt` or `{\rt`.
    pub is_rtf_file: bool,
    /// `%PDF-` in the first 1024 bytes, for a name not ending in `.pdfparser`.
    pub is_pdf_file: bool,
    /// The file starts with `MZ`.
    pub is_pe_file: bool,
    /// Python's `zipfile` opens it and lists at least one name.
    pub is_zip_file: bool,
    /// A PEM or DER certificate that cryptography loads.
    pub is_x509: bool,
    /// The file starts with the Windows shortcut header.
    pub is_lnk_file: bool,
    /// A zip file with `META-INF/MANIFEST.MF`.
    pub is_jar_file: bool,
    /// The file's first lines are ASCII headers with From, Subject and Message-ID, or the mime
    /// type is `message/rfc822`.
    pub is_email_file: bool,
    /// An Office extension, an OLE or RTF file, or a description naming an Office format.
    pub is_office_document: bool,
}

/// What a file's bytes are: the type step's output, kept once per sha256. Every field depends on
/// the bytes alone, so the same bytes have the same facts under any name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeFacts {
    /// libmagic's description, as `file -b -L` prints it, stripped (ace3's `type`).
    pub description: String,
    /// libmagic's mime type, as `file -b --mime-type -L` prints it.
    pub mime: String,
    /// The file starts with the OLE compound file signature.
    pub is_ole_file: bool,
    /// The file starts with `\rt` or `{\rt`.
    pub is_rtf_file: bool,
    /// `%PDF-` in the first 1024 bytes. ace3's `is_pdf_file` is this unless the name ends in
    /// `.pdfparser` (`is_pdf_file`).
    pub has_pdf_marker: bool,
    /// The file starts with `MZ`.
    pub is_pe_file: bool,
    /// Python's `zipfile` opens it and lists at least one name.
    pub is_zip_file: bool,
    /// A zip file with `META-INF/MANIFEST.MF`.
    pub is_jar_file: bool,
    /// A PEM or DER certificate that cryptography loads.
    pub is_x509: bool,
    /// The file starts with the Windows shortcut header.
    pub is_lnk_file: bool,
    /// The file's first lines are ASCII headers with From, Subject and Message-ID, or the mime type
    /// is `message/rfc822`.
    pub is_email_file: bool,
    /// ace3's `is_pcap_file`: a pcap magic number in the first four bytes, or a pcapng section
    /// header with a byte-order magic at bytes 8 to 12.
    pub is_pcap_file: bool,
    /// The first 16 bytes are OneNote's header GUID: the part of ace3's `is_onenote_file` that reads
    /// the bytes (the other part is a `.one` name).
    pub has_onenote_header: bool,
    /// ace3's `is_java_class_file`: the first four bytes are `CAFEBABE`.
    pub is_java_class_file: bool,
    /// `<?xml` in the first 1024 bytes, the test of ace3's two XML modules.
    pub has_xml_marker: bool,
    /// ace3's `BinaryFileAnalyzer._is_eps`: the file starts with the EPS binary header
    /// `C5D0D3C6` or with `%!PS-Adobe-`.
    pub is_eps_file: bool,
    /// The file starts with `#@~^`, the test of ace3's `microsoft_script_encoding_analysis`.
    pub is_encoded_script: bool,
    /// ace3's `is_har_header` on the first 4096 bytes: optional whitespace, `{`, `"log"` and `:`.
    pub has_har_header: bool,
    /// Pillow would open the file (`Image.open`), by its first 1024 bytes: the test ace3's ocr and
    /// qrcode modules make before they read anything (`ace_mod_files::pillow`).
    pub is_image: bool,
    /// Whether node would parse the bytes as JavaScript and a line has a JavaScript keyword: the
    /// part of ace3's `is_javascript_file` that reads the bytes. The type step checks it only when
    /// the mime type or the name it typed the file under says JavaScript, as ace3 gates node; None
    /// when it didn't.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub javascript: Option<bool>,
}

impl AnalysisType for TypeFacts {
    const NAME: &'static str = "file_type_facts";
    const VERSION: u32 = 2;
    const MODULE: &'static str = "file_type";
}

/// The mime types ace3 gates its JavaScript check on (`YARA_META_TYPE_BY_DETAIL`).
pub const JAVASCRIPT_MIME_TYPES: &[&str] = &[
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "text/ecmascript",
];
/// The extensions ace3 gates its JavaScript check on, lowered.
pub const JAVASCRIPT_EXTENSIONS: &[&str] = &[".js", ".mjs", ".cjs", ".jse"];

/// `KNOWN_OFFICE_EXTENSIONS`.
pub const KNOWN_OFFICE_EXTENSIONS: &[&str] = &[
    "doc", "docb", "dochtml", "docm", "docx", "docxml", "dot", "dothtml", "dotm", "dotx", "odt",
    "rtf", "wbk", "wiz", "csv", "dqy", "iqy", "odc", "ods", "slk", "xla", "xlam", "xlk", "xll",
    "xlm", "xls", "xlsb", "xlshtml", "xlsm", "xlsx", "xlt", "xlthtml", "xltm", "xltx", "xlw",
    "odp", "pot", "pothtml", "potm", "potx", "ppa", "ppam", "pps", "ppsm", "ppsx", "ppt",
    "ppthtml", "pptm", "pptx", "pptxml", "pwz", "sldm", "sldx", "thmx",
];

/// `os.path.splitext(path)`: the path and the extension of its last part, with its dot; a dot
/// that only leads the name isn't one.
pub fn splitext(path: &str) -> (&str, &str) {
    let name_start = path.rfind('/').map_or(0, |at| at + 1);
    let Some(dot) = path.rfind('.') else {
        return (path, "");
    };
    if dot < name_start || path[name_start..dot].bytes().all(|byte| byte == b'.') {
        return (path, "");
    }
    path.split_at(dot)
}

/// `is_office_ext`: `os.path.splitext`'s extension, as it is, in the list. It reads the name.
pub fn is_office_ext(path: &str) -> bool {
    splitext(path)
        .1
        .strip_prefix('.')
        .is_some_and(|ext| KNOWN_OFFICE_EXTENSIONS.contains(&ext))
}

/// `is_pdf_file`: the PDF marker, except for the PDF module's own `.pdfparser` output. It reads
/// the name.
pub fn is_pdf_file(path: &str, has_pdf_marker: bool) -> bool {
    has_pdf_marker && !path.ends_with(".pdfparser")
}

/// Whether ace3's file_type would ask node about a file with this mime type at `path`: the mime
/// type or the name's extension says JavaScript.
pub fn asks_about_javascript(path: &str, mime: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    JAVASCRIPT_MIME_TYPES.contains(&mime) || JAVASCRIPT_EXTENSIONS.contains(&splitext(&name).1)
}

/// The part of ace3's `is_javascript_file` that reads the name: node refuses a name that ends in
/// `.js` in another case.
pub fn javascript_name_refused(path: &str) -> bool {
    path.to_lowercase().ends_with(".js") && !path.ends_with(".js")
}

impl TypeFacts {
    /// The description names an Office format.
    pub fn names_office_format(&self) -> bool {
        let lower = self.description.to_lowercase();
        [
            "microsoft powerpoint",
            "microsoft excel",
            "microsoft word",
            "microsoft ooxml",
        ]
        .iter()
        .any(|name| lower.contains(name))
    }

    /// ace3's `is_office_document` for the file at `path`.
    pub fn is_office_document(&self, path: &str) -> bool {
        is_office_ext(path) || self.names_office_format() || self.is_ole_file || self.is_rtf_file
    }

    /// ace3's `is_javascript_file` gated as its file_type gates it, for the file at `path`.
    pub fn is_javascript(&self, path: &str) -> bool {
        asks_about_javascript(path, &self.mime)
            && !javascript_name_refused(path)
            && self.javascript == Some(true)
    }

    /// The tags and `yara_meta` types ace3's file_type gave the file at `path`, in ace3's order.
    pub fn view(&self, path: &str) -> (Vec<&'static str>, Vec<&'static str>) {
        let a = FileTypeAnalysis::from_facts(self, path);
        let tags = [
            (a.is_office_document, "microsoft_office"),
            (a.is_ole_file, "ole"),
            (a.is_rtf_file, "rtf"),
            (a.is_pdf_file, "pdf"),
            (a.is_pe_file, "executable"),
            (a.is_zip_file, "zip"),
            (a.is_lnk_file, "lnk"),
            (a.is_x509, "x509"),
            (a.is_jar_file, "jar"),
            (a.is_email_file, "email"),
        ]
        .into_iter()
        .filter_map(|(set, tag)| set.then_some(tag))
        .collect();
        let mut types = Vec::new();
        if a.mime.starts_with("image/") {
            types.push("image");
        }
        for (set, kind) in [
            (a.is_pdf_file, "document.pdf"),
            (a.is_rtf_file, "document.rtf"),
            (a.is_pe_file, "executable"),
            (a.is_jar_file, "archive.jar"),
            (a.is_x509, "certificate.x509"),
            (a.is_email_file, "email"),
        ] {
            if set {
                types.push(kind);
            }
        }
        if a.mime == "text/html" || a.mime == "application/xhtml+xml" {
            types.push("document.html");
        }
        if self.is_javascript(path) {
            types.push("script.javascript");
        }
        (tags, types)
    }
}

impl FileTypeAnalysis {
    /// ace3's result for the file at `path` with these facts.
    pub fn from_facts(facts: &TypeFacts, path: &str) -> FileTypeAnalysis {
        FileTypeAnalysis {
            file_type: facts.description.clone(),
            mime: facts.mime.clone(),
            is_office_ext: is_office_ext(path),
            is_ole_file: facts.is_ole_file,
            is_rtf_file: facts.is_rtf_file,
            is_pdf_file: is_pdf_file(path, facts.has_pdf_marker),
            is_pe_file: facts.is_pe_file,
            is_zip_file: facts.is_zip_file,
            is_x509: facts.is_x509,
            is_lnk_file: facts.is_lnk_file,
            is_jar_file: facts.is_jar_file,
            is_email_file: facts.is_email_file,
            is_office_document: facts.is_office_document(path),
        }
    }
}

impl AnalysisType for FileTypeAnalysis {
    const NAME: &'static str = "file_type_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "file_type";
}

impl FileTypeAnalysis {
    /// `generate_summary`.
    pub fn summary(&self) -> String {
        let mut result = format!("File Type Analysis: {} ({})", self.file_type, self.mime);
        let flags = [
            (self.is_email_file, " (email)"),
            (
                self.is_office_ext || self.is_office_document,
                " (ms office document)",
            ),
            (self.is_ole_file, " (ole compound file)"),
            (self.is_rtf_file, " (rtf document)"),
            (self.is_pdf_file, " (pdf document)"),
            (self.is_pe_file, " (portable executable)"),
            (self.is_zip_file, " (zip archive)"),
            (self.is_lnk_file, " (windows shortcut)"),
            (self.is_x509, " (x.509 certificate)"),
            (self.is_jar_file, " (java archive)"),
        ];
        for (set, text) in flags {
            if set {
                result.push_str(text);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ace3_s_result_reads_the_name_and_the_facts() {
        let facts = TypeFacts {
            description: "Microsoft Word 2007+".to_owned(),
            mime: "application/pdf".to_owned(),
            has_pdf_marker: true,
            is_zip_file: true,
            ..TypeFacts::default()
        };
        let a = FileTypeAnalysis::from_facts(&facts, "a/b.docx");
        assert!(a.is_office_ext && a.is_pdf_file && a.is_office_document && a.is_zip_file);
        let b = FileTypeAnalysis::from_facts(&facts, "a/b.docx.pdfparser");
        assert!(!b.is_office_ext && !b.is_pdf_file && b.is_office_document);
        assert!(!is_office_ext("a/b.DOCX") && !is_office_ext(".docx"));
        assert_eq!(splitext("a.b/c"), ("a.b/c", ""));
        assert_eq!(splitext("..a.b"), ("..a", ".b"));
        let (tags, types) = facts.view("a/b.docx");
        assert_eq!(tags, ["microsoft_office", "pdf", "zip"]);
        assert_eq!(types, ["document.pdf"]);
    }

    #[test]
    fn javascript_is_gated_by_the_mime_type_or_the_name() {
        let mut facts = TypeFacts {
            mime: "text/plain".to_owned(),
            javascript: Some(true),
            ..TypeFacts::default()
        };
        assert!(facts.is_javascript("x/a.js"));
        assert!(facts.is_javascript("x/a.JSE"));
        // node refuses a .js name in another case
        assert!(!facts.is_javascript("x/a.JS"));
        assert!(!facts.is_javascript("x/a.txt"));
        facts.mime = "application/javascript".to_owned();
        assert!(facts.is_javascript("x/a.txt"));
        facts.javascript = None;
        assert!(!facts.is_javascript("x/a.js"));
        assert!(asks_about_javascript("a.MJS", "x") && !asks_about_javascript("a.txt", "x"));
    }

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "type": "Zip archive data", "mime": "application/zip", "is_office_ext": false,
            "is_ole_file": false, "is_rtf_file": false, "is_pdf_file": false, "is_pe_file": false,
            "is_zip_file": true, "is_x509": false, "is_lnk_file": false, "is_jar_file": true,
            "is_email_file": false, "is_office_document": false,
        });
        let read: FileTypeAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert_eq!(
            read.summary(),
            "File Type Analysis: Zip archive data (application/zip) (zip archive) (java archive)"
        );
        let mut extra = details;
        extra["x"] = json!(1);
        assert!(serde_json::from_value::<FileTypeAnalysis>(extra).is_err());
    }
}
