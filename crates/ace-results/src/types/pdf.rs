//! `pdf_analysis`: what a PDF's encryption is, when it opens with the empty password (ace3's
//! `PDFAnalysis`, `saq/modules/file_analysis/pdf.py`). The rest of the module's output is files.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `pdf_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PdfAnalysis {
    /// The encryption of a PDF that opens with no password. Absent for any other PDF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
}

/// What ace3 records from pikepdf's `pdf.encryption`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Encryption {
    /// The encryption dictionary's `/Filter`, such as `/Standard`.
    pub filter: String,
    #[serde(rename = "V")]
    pub v: i64,
    #[serde(rename = "R")]
    pub r: i64,
    #[serde(rename = "P")]
    pub p: i64,
    /// The length of the file's key.
    pub bits: i64,
    /// How streams are encrypted: `rc4`, `aes`, `aesv3`, `none` or `unknown`.
    pub method: String,
    /// Whether the empty password is also the owner's.
    pub owner_password_empty: bool,
    pub permissions: Permissions,
}

/// pikepdf's `pdf.allow`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub accessibility: bool,
    pub extract: bool,
    pub modify_annotation: bool,
    pub modify_assembly: bool,
    pub modify_form: bool,
    pub modify_other: bool,
    pub print_lowres: bool,
    pub print_highres: bool,
}

impl AnalysisType for PdfAnalysis {
    const NAME: &'static str = "pdf_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "pdf_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        for details in [
            json!({}),
            json!({"encryption": {
                "filter": "/Standard", "V": 4, "R": 4, "P": -4, "bits": 128, "method": "aes",
                "owner_password_empty": false,
                "permissions": {
                    "accessibility": true, "extract": true, "modify_annotation": true,
                    "modify_assembly": true, "modify_form": true, "modify_other": true,
                    "print_lowres": true, "print_highres": true,
                },
            }}),
        ] {
            let read: PdfAnalysis = serde_json::from_value(details.clone()).expect("reads");
            assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        }
        assert!(serde_json::from_value::<PdfAnalysis>(json!({"x": 1})).is_err());
    }
}
