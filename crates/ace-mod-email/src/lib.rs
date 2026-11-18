//! The email module, a port of ace3's `EmailAnalyzer` (`saq/modules/email/rfc822.py`) onto
//! mail-parser.
//!
//! It reads an RFC 822 message's headers and addresses into an `email_analysis` result and adds
//! its senders, recipients, subject, message id and first hop as observables. An Office 365
//! journal report is analyzed as the original message inside it, with the recipients from the
//! report's meta block. Each body part and attachment becomes a file, under ace3's names and
//! with its `type=email.attachment` tag, followed by a headers file and a combined file for YARA.
//!
//! Python's `email` package decides much of what ace3 sees, so `py` reproduces the parts of it
//! ace3 relies on.
//!
//! ace3's brotex whitelist (`saq/whitelist.py`), a file the module watched, is two analyst-edited
//! lists here (PLAN.md 5.14), which the core sends with each task: `SENDER_WHITELIST`, ace3's
//! `smtp_from`, matched against the `From` address, and `RECIPIENT_WHITELIST`, ace3's `smtp_to`,
//! against each `To` address and envelope recipient. ace3's entries were case-blind substrings; an
//! entry here says how it matches. A message one matches, or an outbound journaled one under
//! `scan_inbound_only`, is whitelisted as in ace3: the file gets the `whitelisted` tag and directive,
//! nothing is extracted, and the core stops the root's analysis. ace3 adds no analysis to the file;
//! here the result that carries the tag has empty details and ace3's summary for it, "Email Analysis:
//! (whitelisted email)", since a result is how a module adds to the file it analyzed.

mod analyze;
pub mod headers;
mod mime;
pub mod naming;
mod parts;
pub mod py;
mod settings;

use std::fs;

use ace_results::types::email::EmailAnalysis;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::{AnalysisType, NewFile, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::takes::{Case, Condition, Match, Takes, Text};
use ace_sdk::{
    FileOutputError, ListSpec, Manifest, Module, ModuleError, Outcome, Parser, TaskContext,
};
use mail_parser::MessageParser;

pub use analyze::is_local_email_domain;
pub use settings::{EmailAnalyzerSettings, ProviderHeaders};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<EmailAnalyzer>();

/// ace3's `smtp_from` whitelist.
pub const SENDER_WHITELIST: ListSpec = ListSpec {
    name: "email_sender_whitelist",
    description: "Emails whose From address an entry matches are whitelisted: the email module adds \
                  the whitelisted tag and directive to the file and extracts nothing, and the root's \
                  analysis stops. ace3's smtp_from whitelist, whose entries were case-blind substrings.",
    typed: false,
};

/// ace3's `smtp_to` whitelist.
pub const RECIPIENT_WHITELIST: ListSpec = ListSpec {
    name: "email_recipient_whitelist",
    description: "Emails with a To address or envelope recipient an entry matches are whitelisted, as \
                  with the sender whitelist. ace3's smtp_to whitelist, whose entries were case-blind \
                  substrings.",
    typed: false,
};

/// The email module.
pub struct EmailAnalyzer;

impl Module for EmailAnalyzer {
    const NAME: &'static str = "email_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    const LISTS: &'static [ListSpec] = &[SENDER_WHITELIST, RECIPIENT_WHITELIST];
    type Output = EmailAnalysis;
    type Settings = EmailAnalyzerSettings;

    fn init(_: &EmailAnalyzerSettings) -> Result<Self, ModuleError> {
        Ok(EmailAnalyzer)
    }

    fn takes(_: &EmailAnalyzerSettings) -> Takes {
        let file_type = FileTypeAnalysis::MODULE;
        Takes::everything()
            // the headers file is this module's own output, and looks like an email
            .and(
                Condition::Path(Text::ends_with(".headers", Case::Exact)).negated(),
                "a headers file",
            )
            // ace3 waits for file_type, and reads whether this is an email from its result
            .and(
                Condition::HasResult(file_type.to_owned()),
                "no file type analysis",
            )
            .and(
                Condition::result_text(file_type, "type", Text::exact(Match::NotEmpty)),
                "file_type has no description",
            )
            .and(
                Condition::Any(vec![
                    Condition::result_text(file_type, "type", Text::contains("RFC 822 mail")),
                    Condition::result_text(file_type, "type", Text::contains("message/rfc822")),
                    Condition::result_text(file_type, "mime", Text::contains("message/rfc822")),
                    Condition::directive(analyze::DIRECTIVE_ORIGINAL_EMAIL),
                    Condition::result_true(file_type, "is_email_file"),
                ]),
                "not an RFC 822 message",
            )
    }
}

impl Parser for EmailAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<EmailAnalyzerSettings>,
    ) -> Result<Outcome<EmailAnalysis>, ModuleError> {
        // `takes` checked whether file_type's result calls this an email
        let file = ctx.input_file()?;
        let bytes = fs::read(&file.local_path)?;
        ctx.check_cancelled()?;

        // ace3 parses through a text wrapper with universal newlines (BytesParser.parse), which
        // turns every \r\n and \r into \n before the parser sees them: header values, bodies
        // and extracted parts all come out with \n line endings
        let bytes = universal_newlines(&bytes);
        let Some(message) = MessageParser::new().parse(&bytes) else {
            return Ok(Outcome::Skipped("the message doesn't parse".to_owned()));
        };
        let root = mime::Node::message(message.root());
        let whitelists = analyze::Whitelists {
            senders: ctx.list(&SENDER_WHITELIST)?,
            recipients: ctx.list(&RECIPIENT_WHITELIST)?,
            now: ctx.now(),
        };
        let directives = &ctx.observable().directives;
        let analysis =
            match analyze::analyze_headers(&root, file, directives, ctx.settings(), &whitelists) {
                Ok(analysis) => analysis,
                Err(analyze::Skip::Whitelisted { analyzed, why }) => {
                    let mut result = ResultEnvelope::new(EmailAnalysis {
                        parsing_error: None,
                        extraction_errors: Vec::new(),
                        email: None,
                    });
                    result.analyzed = analyzed;
                    result.summary = Some(WHITELISTED_SUMMARY.to_owned());
                    tracing::debug!("{why}");
                    return Ok(Outcome::Done(result));
                }
                Err(analyze::Skip::BadList(error)) => {
                    return Err(ModuleError::other(format!("a whitelist: {error}")));
                }
            };
        let mut result = analysis.result;
        let mut analyzed = analysis.analyzed;

        ctx.check_cancelled()?;
        let writer = ContextWriter(ctx);
        let mut extractor = parts::Extractor::new(file, &writer, analysis.target_message_id);
        extractor.extract(analysis.target);
        let mut names = extractor.names;
        let extracted = extractor.out;
        if !extracted.errors.is_empty() {
            analyzed.add_tag(parts::TAG_EMAIL_PARSE_INCOMPLETE);
        }
        result.files = extracted.files;
        if let Some(email) = result.details.email.as_mut() {
            let log = &mut email.log_entry;
            log.attachment_count = extracted.attachments.len() as u64;
            for attachment in &extracted.attachments {
                log.attachment_sizes.push(attachment.size);
                log.attachment_types.push(attachment.content_type.clone());
                log.attachment_names.push(attachment.path.clone());
                log.attachment_hashes.push(attachment.sha256.clone());
            }
            let headers_text = email
                .headers
                .iter()
                .map(|[name, value]| format!("{name}: {value}"))
                .collect::<Vec<_>>()
                .join("\n");
            for file in headers_files(
                &writer,
                &mut names,
                file.path.as_str(),
                &headers_text,
                &extracted.attachments,
            )? {
                result.files.push(file);
            }
        }
        result.details.extraction_errors = extracted.errors;
        result.analyzed = analyzed;
        let summary = summary(&result.details);
        if let Some(summary) = summary {
            result.summary = Some(summary);
        }
        Ok(Outcome::Done(result))
    }
}

/// The task context as the part extractor's file writer.
struct ContextWriter<'c>(&'c TaskContext<EmailAnalyzerSettings>);

impl parts::Writer for ContextWriter<'_> {
    fn write(
        &self,
        path: &str,
        bytes: &[u8],
        yara_meta: &[YaraMeta],
    ) -> Result<NewFile, FileOutputError> {
        self.0.write_file(path, bytes, yara_meta)
    }
}

/// The headers file and the combined file: the message's headers on their own, and the headers
/// followed by each unnamed body part, so YARA rules can match on either. The email module
/// doesn't analyze either one.
fn headers_files(
    writer: &dyn parts::Writer,
    names: &mut naming::OutputNames,
    email_path: &str,
    headers: &str,
    attachments: &[parts::Attachment],
) -> Result<Vec<NewFile>, ModuleError> {
    let (dir, base) = match email_path.rsplit_once('/') {
        Some((dir, base)) => (format!("{dir}/"), base),
        None => (String::new(), email_path),
    };
    let path_with = |suffix: &str| {
        format!(
            "{dir}{}",
            naming::shorten_basename_for_suffix(base, suffix, 255)
        )
    };
    let mut files = Vec::new();
    let headers_path = path_with(".headers");
    if !names.is_taken(&headers_path) {
        let mut file = writer.write(
            &headers_path,
            headers.as_bytes(),
            &[yara_meta("email.headers")],
        )?;
        file.exclude_modules.push(EmailAnalyzer::NAME.to_owned());
        names.take(&headers_path);
        files.push(file);
    }
    let combined_path = path_with(".combined");
    if !names.is_taken(&combined_path) {
        let mut combined = headers.as_bytes().to_vec();
        combined.extend_from_slice(b"\n\n");
        for attachment in attachments.iter().filter(|a| a.path.contains("unknown_")) {
            combined.extend_from_slice(&attachment.bytes);
            combined.extend_from_slice(b"\n\n");
        }
        let mut file = writer.write(&combined_path, &combined, &[yara_meta("email.combined")])?;
        file.exclude_modules.push(EmailAnalyzer::NAME.to_owned());
        names.take(&combined_path);
        files.push(file);
    }
    Ok(files)
}

fn yara_meta(value: &str) -> YaraMeta {
    YaraMeta::new("type", value).expect("a valid yara_meta tag")
}

/// `\r\n` and `\r` as `\n`, as Python's `TextIOWrapper` reads them by default.
fn universal_newlines(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            out.push(b'\n');
            if bytes.get(i + 1) == Some(&b'\n') {
                i += 1;
            }
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    out
}

/// `EmailAnalysis.generate_summary` for a whitelisted email.
pub const WHITELISTED_SUMMARY: &str = "Email Analysis: (whitelisted email)";

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
