//! The results of PLAN.md 7.5 batch 7's modules, which `ace-mod-encrypted` writes: ace3's
//! `ZipEncryptionAnalysis` (`saq/modules/email/encryption/zip.py`), `RarEncryptionAnalysis` (`rar.py`)
//! and `PDFEncryptionAnalysis` (`pdf.py`), with ace3's keys. Like `msoffice_encryption_analysis`, each
//! holds the passwords tried on an encrypted file, from the body of the email that carried it, in the
//! clear.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `zip_encryption_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ZipEncryptionAnalysis {
    /// ace3 has this key and never sets it.
    pub encryption_info: Option<String>,
    /// An email with a body carried the file.
    pub email: bool,
    /// The email's body as text, cut at the module's `byte_limit`.
    pub email_body: Option<String>,
    /// The passwords tried, from the body, sorted.
    pub word_list: Vec<String>,
    /// The password John would have found, as ace3 reads it from John's answer: up to a `:`.
    pub password: Option<String>,
    /// Why nothing was extracted.
    pub error: Option<String>,
}

impl AnalysisType for ZipEncryptionAnalysis {
    const NAME: &'static str = "zip_encryption_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "zip_encryption_analyzer";
}

/// The details of a `rar_encryption_analysis` result, ace3's same keys as a zip's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RarEncryptionAnalysis {
    /// ace3 has this key and never sets it.
    pub encryption_info: Option<String>,
    /// An email with a body carried the file.
    pub email: bool,
    /// The email's body as text, cut at the module's `byte_limit`.
    pub email_body: Option<String>,
    /// The passwords tried, from the body, sorted.
    pub word_list: Vec<String>,
    /// The password John would have found, as ace3 reads it from John's answer: up to a `:`.
    pub password: Option<String>,
    /// Why nothing was extracted.
    pub error: Option<String>,
}

impl AnalysisType for RarEncryptionAnalysis {
    const NAME: &'static str = "rar_encryption_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "rar_encryption_analyzer";
}

/// The details of a `pdf_encryption_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PdfEncryptionAnalysis {
    /// An email carried the file, with a body or without one.
    pub email: bool,
    /// The email's body as text, cut at the module's `byte_limit`.
    pub email_body: Option<String>,
    /// The passwords tried, from the body, sorted.
    pub word_list: Vec<String>,
    /// The user password that opened it.
    pub password: Option<String>,
    /// Why no copy was written.
    pub error: Option<String>,
}

impl AnalysisType for PdfEncryptionAnalysis {
    const NAME: &'static str = "pdf_encryption_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "pdf_encryption_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let archive = json!({
            "encryption_info": null,
            "email": true,
            "email_body": "the password is Secr3tPw\n\n",
            "word_list": ["Secr3tPw", "pass"],
            "password": "Secr3tPw",
            "error": null,
        });
        let zip: ZipEncryptionAnalysis = serde_json::from_value(archive.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&zip).expect("writes"), archive);
        let rar: RarEncryptionAnalysis = serde_json::from_value(archive.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&rar).expect("writes"), archive);
        let mut pdf = archive;
        pdf.as_object_mut()
            .expect("an object")
            .remove("encryption_info");
        let read: PdfEncryptionAnalysis = serde_json::from_value(pdf.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), pdf);
        pdf["extra"] = json!(1);
        assert!(serde_json::from_value::<PdfEncryptionAnalysis>(pdf).is_err());
    }
}
