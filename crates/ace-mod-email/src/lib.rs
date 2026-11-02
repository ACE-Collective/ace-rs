//! The email module, a port of ace3's `EmailAnalyzer` (`saq/modules/email/rfc822.py`) onto
//! mail-parser.
//!
//! It reads an RFC 822 message's headers and addresses into an `email_analysis` result and adds
//! its senders, recipients, subject, message id and first hop as observables. An Office 365
//! journal report is analyzed as the original message inside it, with the recipients from the
//! report's meta block.
//!
//! Python's `email` package decides much of what ace3 sees, so `py` reproduces the parts of it
//! ace3 relies on.

mod analyze;
mod headers;
mod mime;
pub mod py;
mod settings;

use std::fs;

use ace_results::ObservableKind;
use ace_results::types::email::EmailAnalysis;
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use mail_parser::MessageParser;

pub use settings::{EmailAnalyzerSettings, ProviderHeaders};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<EmailAnalyzer>();

/// The email module.
pub struct EmailAnalyzer;

impl Module for EmailAnalyzer {
    const NAME: &'static str = "email_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = EmailAnalysis;
    type Settings = EmailAnalyzerSettings;

    fn init(_: &EmailAnalyzerSettings) -> Result<Self, ModuleError> {
        Ok(EmailAnalyzer)
    }
}

impl Parser for EmailAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<EmailAnalyzerSettings>,
    ) -> Result<Outcome<EmailAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        // the headers file is this module's own output, and looks like an email
        if file.path.as_str().ends_with(".headers") {
            return Ok(Outcome::Skipped("a headers file".to_owned()));
        }
        let bytes = fs::read(&file.local_path)?;
        let directives = &ctx.observable().directives;
        let is_email = file.mime_type.as_deref() == Some("message/rfc822")
            || directives
                .iter()
                .any(|d| d == analyze::DIRECTIVE_ORIGINAL_EMAIL)
            || is_email_file(&bytes);
        if !is_email {
            return Ok(Outcome::Skipped("not an RFC 822 message".to_owned()));
        }
        ctx.check_cancelled()?;

        let Some(message) = MessageParser::new().parse(&bytes) else {
            return Ok(Outcome::Skipped("the message doesn't parse".to_owned()));
        };
        let root = mime::Node::message(message.root());
        let analysis =
            match analyze::analyze_headers(&root, file, directives, ctx.settings(), ctx.now()) {
                Ok(analysis) => analysis,
                Err(analyze::Skip::Outbound) => {
                    return Ok(Outcome::Skipped(
                        "an outbound journaled message, and scan_inbound_only is set".to_owned(),
                    ));
                }
            };
        let mut result = analysis.result;
        result.analyzed = analysis.analyzed;
        let summary = summary(&result.details);
        if let Some(summary) = summary {
            result.summary = Some(summary);
        }
        Ok(Outcome::Done(result))
    }
}

/// `EmailAnalysis.generate_summary`.
fn summary(details: &EmailAnalysis) -> Option<String> {
    if let Some(error) = &details.parsing_error {
        return Some(error.clone());
    }
    let email = details.email.as_ref()?;
    let mut summary = if details.extraction_errors.is_empty() {
        "Email Analysis:".to_owned()
    } else {
        format!(
            "Email Analysis [partial extraction: {} error(s)]:",
            details.extraction_errors.len()
        )
    };
    if let Some(from) = &email.from {
        summary = format!("{summary} From {from}");
    }
    if let Some(to) = email.env_rcpt_to.first().or(email.to.first()) {
        summary = format!("{summary} To {to}");
    }
    if let Some(subject) = email.decoded_subject.as_ref().or(email.subject.as_ref()) {
        summary = format!("{summary} Subject {subject}");
    }
    Some(summary)
}

/// `is_email_file` in ace3's `is_file_type.py`: the file starts with plain ASCII header lines
/// that include From, Subject and Message-ID.
fn is_email_file(bytes: &[u8]) -> bool {
    const COMMON: [&str; 3] = ["from", "subject", "message-id"];
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut found: Vec<String> = Vec::new();
    for line in text.split_inclusive(['\n', '\r']) {
        if !line.is_ascii() {
            return false;
        }
        let line = line.trim_end_matches(['\n', '\r']);
        // a continuation
        if line.starts_with(char::is_whitespace) && !line.trim().is_empty() {
            continue;
        }
        if line.trim().is_empty() {
            return false;
        }
        let Some((name, _)) = line.split_once(':') else {
            return false;
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return false;
        }
        let name = name.to_lowercase();
        if COMMON.contains(&name.as_str()) && !found.contains(&name) {
            found.push(name);
        }
        if found.len() == COMMON.len() {
            return true;
        }
    }
    false
}
