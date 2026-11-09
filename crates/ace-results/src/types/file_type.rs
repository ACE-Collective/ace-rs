//! `file_type_analysis`: what kind of file this is (ace3's `FileTypeAnalysis`,
//! `saq/modules/file_analysis/file_type.py`). `ace-mod-files` writes it (PLAN.md 7.5 batch 2).
//! Other modules read it: those ace3 makes depend on `file_type`.

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
