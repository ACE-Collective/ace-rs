//! `msoffice_encryption_analysis`: an encrypted Office file and the passwords tried on it (ace3's
//! `MSOfficeEncryptionAnalysis`, `saq/modules/email/encryption/msoffice.py`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `msoffice_encryption_analysis` result, as ace3 keeps them. The password, the
/// candidates and the body they came from are stored in the clear.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MsofficeEncryptionAnalysis {
    /// An email carried the file.
    pub email: bool,
    /// The email's body as text, cut at the module's `byte_limit`. None when there's no email or it
    /// has no body.
    pub email_body: Option<String>,
    /// The passwords to try: the two Office's own defaults, then those from the body, sorted.
    pub word_list: Vec<String>,
    /// The password that opened it.
    pub password: Option<String>,
    /// Why the file wasn't decrypted.
    pub error: Option<String>,
    /// ace3 has this key and never sets it.
    pub encryption_info: Option<String>,
}

impl AnalysisType for MsofficeEncryptionAnalysis {
    const NAME: &'static str = "msoffice_encryption_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "msoffice_encryption_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "email": true,
            "email_body": "the password is Secr3tPw\n",
            "word_list": ["VelvetSweatshop", "/01Hannes Ruescher/01", "Secr3tPw"],
            "password": "Secr3tPw",
            "error": null,
            "encryption_info": null,
        });
        let read: MsofficeEncryptionAnalysis =
            serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);

        let mut unknown = details;
        unknown["extra"] = json!(1);
        assert!(serde_json::from_value::<MsofficeEncryptionAnalysis>(unknown).is_err());
    }
}
