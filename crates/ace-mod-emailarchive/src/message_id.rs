//! The Message-ID analyzer, a port of ace3's `MessageIDAnalyzerV2` (`saq/modules/email/message_id.py`).
//!
//! For a `message_id` observable whose email isn't already in the alert, it asks the core for the
//! newest archived email with that Message-ID (the `archived-email` read), which the core decrypts
//! and puts in the root, and adds it as `<sha256 of the Message-ID>.rfc822`, tagged
//! `decrypted_email` and given `type=email` for YARA, for the email module to parse, as ace3 does.
//!
//! ace3 first looks up the tree for an email analysis with this Message-ID (`search_down`), which
//! would be the email that added the observable. Here that's whether the email module's result added
//! it (`Module::READS_ADDED_BY`), which also excludes this module on it, as ace3's does.

use ace_results::FileRole;
use ace_results::types::email::EmailAnalysis;
use ace_results::types::email_archive::MessageIdAnalysis;
use ace_results::{AlertPath, AnalysisType, NewFile, ObservableKind, ResultEnvelope, Sha256};
use ace_sdk::reads::{ArchivedEmail, ArchivedEmailRequest, Read, ReadKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use sha2::{Digest, Sha256 as Sha256Hasher};

use crate::DECRYPTED_EMAIL;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<MessageIdAnalyzer>();

/// The Message-ID analyzer.
pub struct MessageIdAnalyzer;

impl Module for MessageIdAnalyzer {
    const NAME: &'static str = "message_id_analyzer_v2";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::MessageId];
    const READS_ADDED_BY: bool = true;
    const READS: &'static [Read] = &[ArchivedEmail::READ];
    type Output = MessageIdAnalysis;
    type Settings = ();

    fn init(_settings: &()) -> Result<Self, ModuleError> {
        Ok(MessageIdAnalyzer)
    }
}

/// The name ace3 gives the email: the Message-ID's SHA-256, so no name is too long.
pub fn file_name(message_id: &str) -> String {
    format!(
        "{}.rfc822",
        Sha256Hasher::digest(message_id.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

impl Lookup for MessageIdAnalyzer {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<MessageIdAnalysis>, ModuleError> {
        let message_id = &ctx.observable().value;
        if ctx.added_by().iter().any(|m| m == EmailAnalysis::MODULE) {
            tracing::debug!("already have email analysis for {message_id}");
            return Ok(Outcome::Skipped("its email is in the alert".to_owned()));
        }
        let answer = ctx
            .read::<ArchivedEmail>(&ArchivedEmailRequest::default())
            .await?;
        let email = match (answer.email, answer.error) {
            (Some(email), _) => email,
            (None, Some(error)) => {
                tracing::error!("unable to get archived email {message_id}: {error}");
                return Ok(Outcome::Skipped("didn't open".to_owned()));
            }
            (None, None) => {
                tracing::info!("email {message_id} is not archived");
                return Ok(Outcome::Skipped("not archived".to_owned()));
            }
        };
        if email.size == 0 {
            tracing::info!("got 0 bytes for {message_id}");
            return Ok(Outcome::Skipped("an empty email".to_owned()));
        }
        let path = AlertPath::new(file_name(message_id)).map_err(ModuleError::other)?;
        let sha256: Sha256 = email.sha256.parse().map_err(ModuleError::other)?;
        let mut file = NewFile::new(path, sha256, email.size);
        file.add_tag(DECRYPTED_EMAIL);
        file.set_role(FileRole::EMAIL);
        let mut result = ResultEnvelope::new(MessageIdAnalysis::default());
        result.files.push(file);
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_name_is_the_message_id_s_sha256() {
        assert_eq!(
            super::file_name("x"),
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881.rfc822"
        );
    }
}
