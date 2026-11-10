//! ace3's modules for encrypted email attachments other than Office's (PLAN.md 7.5 batch 7):
//! `zip_encryption_analyzer`, `rar_encryption_analyzer` and `pdf_encryption_analyzer`
//! (`saq/modules/email/encryption/{zip,rar,pdf}.py`).
//!
//! ace3 cuts candidate passwords from the body of the email that carried the file, hands them to John
//! the Ripper as a wordlist with no rules, then opens the file with the one John found: 7z for a zip,
//! unrar for a RAR, pikepdf for a PDF. A task process starts no process, and 7.3 dropped John, so each
//! module here tries the same candidates itself, as `msoffice_encryption_analyzer` does (4.11), with
//! the format's own library: the zip crate, libunrar and libqpdf. The candidates are 4.11's,
//! `ace_mod_msoffice::words_from_body`.
//!
//! What John accepts is what's kept, not what the library would: John checks a PDF's user password
//! and never its owner's, and ace3 reads a zip's or a RAR's password from John's answer up to its first
//! `:`. Each module says where its check follows John's (`zip::crack`, `rar::crack`, `pdf::crack`).
//!
//! Bounds: at most `list_limit` candidates (5,000), each costing what the format's key derivation
//! costs, which the file fixes or caps (`docs/measurements/encrypted.md`). The candidates stop when
//! what's left of the task is what extracting needs, and the result is ace3's when John is stopped:
//! no password.

pub mod pdf;
pub mod rar;
pub mod zip;

use std::fs;
use std::time::{Duration, Instant};

use ace_mod_msoffice::WordlistLimits;
use ace_results::Detection;
use ace_sdk::{CarryingEmail, ModuleError, TaskContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use pdf::PdfEncryptionAnalyzer;
pub use rar::RarEncryptionAnalyzer;
pub use zip::ZipEncryptionAnalyzer;

/// ace3's built-in `EMAIL_ENCRYPTED_DECRYPTED` signature.
pub const SIGNATURE_UUID: &str = "ef715326-081e-4ece-97ba-02817b5a28cd";
const DETECTION: &str = "Was able to decrypt based on contents of email.";
const DIRECTIVE_EXTRACT_URLS: &str = "extract_urls";
/// What's kept for the rest of a task when it stops trying passwords: extracting or decrypting the
/// file and writing it.
/// tool_sandbox.max_output_bytes: ace3 stops a tool that writes more to its stdout, and the module
/// then says the tool didn't finish.
pub(crate) const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

const AFTER_CRACKING: Duration = Duration::from_secs(10);

macro_rules! wordlist_settings {
    ($(#[$doc:meta])* $name:ident, $range_high:expr) => {
        $(#[$doc])*
        ///
        /// ace3's section of the module, but for `john_bin_path`, which names a program a task can't
        /// start, and the zip's `extract_timeout`, 7z's.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields, default)]
        pub struct $name {
            /// The shortest password to try.
            pub range_low: usize,
            /// The longest password to try.
            pub range_high: usize,
            /// How much of the email's body to look at, in characters.
            pub byte_limit: usize,
            /// The most passwords to try from the email.
            pub list_limit: usize,
        }

        impl Default for $name {
            /// ace3's `saq.default.yaml`.
            fn default() -> Self {
                $name {
                    range_low: 4,
                    range_high: $range_high,
                    byte_limit: 1024,
                    list_limit: 5000,
                }
            }
        }

        impl Wordlist for $name {
            fn limits(&self) -> WordlistLimits {
                WordlistLimits {
                    range_low: self.range_low,
                    range_high: self.range_high,
                    byte_limit: self.byte_limit,
                    list_limit: self.list_limit,
                }
            }
        }
    };
}

/// Settings that say how to cut candidates from a body.
pub trait Wordlist {
    fn limits(&self) -> WordlistLimits;
}

wordlist_settings!(
    /// The zip and RAR modules' settings.
    ArchiveSettings,
    10
);
wordlist_settings!(
    /// The PDF module's settings.
    PdfSettings,
    11
);

/// What the carrying email gave a module.
#[derive(Debug)]
pub(crate) enum Carried {
    /// No email carried the file.
    Absent,
    /// An email did, with no body.
    NoBody,
    /// Its body as text, cut at `byte_limit`, and the candidates in it in the order they first appear.
    Body { text: String, words: Vec<String> },
    /// html2text raised on the body.
    Raised(String),
}

/// The carrying email's body and the candidates in it. Call it once the email isn't pending.
pub(crate) fn carried<S: Wordlist>(ctx: &TaskContext<S>) -> Result<Carried, ModuleError> {
    Ok(match ctx.carrying_email() {
        CarryingEmail::Pending | CarryingEmail::Absent => Carried::Absent,
        CarryingEmail::NoBody => Carried::NoBody,
        CarryingEmail::Body(path) => {
            let body = fs::read(path)?;
            match ace_mod_msoffice::words_from_body(&body, ctx.settings().limits()) {
                Ok((text, words)) => Carried::Body { text, words },
                Err(error) => Carried::Raised(error.message),
            }
        }
    })
}

/// The candidates as the result keeps them: sorted, where ace3 has a set's order, which changes from
/// run to run.
pub(crate) fn sorted(words: &[String]) -> Vec<String> {
    let mut sorted = words.to_vec();
    sorted.sort();
    sorted
}

/// When a task stops trying candidates.
pub(crate) fn cracking_deadline<S>(ctx: &TaskContext<S>) -> Instant {
    Instant::now() + ctx.time_left().saturating_sub(AFTER_CRACKING)
}

/// What ace3 reads as the password from John's `--show` line for a zip or a RAR, whose fields are
/// split at `:`: the password up to its first `:`.
pub(crate) fn as_john_shows(password: &str) -> &str {
    password.split(':').next().unwrap_or_default()
}

pub(crate) fn decrypted_detection() -> Detection {
    Detection {
        signature_uuid: Some(SIGNATURE_UUID.to_owned()),
        ..Detection::new(DETECTION)
    }
}

/// ace3's `generate_summary` for the three, which differ only in their name.
pub(crate) fn summarize(
    name: &str,
    error: Option<&str>,
    password: Option<&str>,
    email: bool,
    email_body: Option<&str>,
    word_list: &[String],
) -> String {
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        return format!("{name}: {error}");
    }
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        return format!("{name}: password {password}");
    }
    if !email {
        return format!("{name}: no associated email detected");
    }
    if email_body.is_none_or(str::is_empty) {
        return format!("{name}: email body cannot be determined");
    }
    if word_list.is_empty() {
        return format!("{name}: word list could not be created from email");
    }
    format!("{name}: password not available")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn john_shows_a_password_up_to_its_colon() {
        assert_eq!(as_john_shows("ab:cd1234"), "ab");
        assert_eq!(as_john_shows("Secr3tPw"), "Secr3tPw");
        assert_eq!(as_john_shows(":x"), "");
    }

    #[test]
    fn the_summary_says_what_stopped_it_first() {
        let words = ["pass".to_owned()];
        assert_eq!(
            summarize("Z", Some("e"), Some("p"), true, Some("b"), &words),
            "Z: e"
        );
        assert_eq!(
            summarize("Z", None, Some("p"), true, Some("b"), &words),
            "Z: password p"
        );
        assert_eq!(
            summarize("Z", None, None, false, None, &[]),
            "Z: no associated email detected"
        );
        assert_eq!(
            summarize("Z", None, None, true, Some(""), &[]),
            "Z: email body cannot be determined"
        );
        assert_eq!(
            summarize("Z", None, None, true, Some("b"), &[]),
            "Z: word list could not be created from email"
        );
        assert_eq!(
            summarize("Z", None, None, true, Some("b"), &words),
            "Z: password not available"
        );
    }
}
