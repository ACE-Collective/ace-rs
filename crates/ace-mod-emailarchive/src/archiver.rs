//! The email archiver, a port of ace3's `EmailArchiveAction` (`saq/modules/email/archive.py`).
//!
//! For an email file with the `archive` directive, which ace3's collectors give the email an alert
//! came in as, it hands the email to the archive with its Message-ID and envelope recipients, as the
//! `email-archive` write. The core reads the file from the bucket, gzips and encrypts it with ACE's
//! key, and writes the archive's rows in the task's end, which also lands this result with the
//! archive's id; once the root's analysis is done, it indexes the URLs below the email, as ace3's
//! post-analysis does. As in ace3, it's off until a site turns it on, and runs only in the `email`
//! mode.
//!
//! ace3 copies an email it can't archive, for a missing Message-ID or envelope recipient, to
//! `review/rfc822/` on its node. ace4 keeps no file outside an alert, so it logs that and stores
//! nothing; the email is still the root's file.

use ace_results::types::email::EmailAnalysis;
use ace_results::types::email_archive::{EmailArchiveResults, archive_path};
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::writes::{ArchivedEmailRecord, EmailArchive, Write, WriteKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::DECRYPTED_EMAIL;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<EmailArchiver>();

/// ace3's directive for an email to archive.
pub const ARCHIVE: &str = "archive";

/// The module's settings: ace3's.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct EmailArchiverSettings {
    /// ace3 declares this and reads it nowhere: the archive's retention is its partitions', the
    /// core's `ACE4_EMAIL_ARCHIVE_RETENTION_DAYS`.
    pub expiration_days: u32,
}

impl Default for EmailArchiverSettings {
    fn default() -> Self {
        EmailArchiverSettings { expiration_days: 7 }
    }
}

/// The email archiver.
pub struct EmailArchiver;

impl Module for EmailArchiver {
    const NAME: &'static str = "email_archiver";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[EmailAnalysis::MODULE];
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[ARCHIVE];
    const ENABLED_BY_DEFAULT: bool = false;
    /// For the file's tags: ace3 won't archive an email it took out of the archive.
    const READS_TREE: bool = true;
    const WRITES: &'static [Write] = &[EmailArchive::WRITE];
    type Output = EmailArchiveResults;
    type Settings = EmailArchiverSettings;

    fn init(_settings: &EmailArchiverSettings) -> Result<Self, ModuleError> {
        Ok(EmailArchiver)
    }
}

impl Lookup for EmailArchiver {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<EmailArchiverSettings>,
    ) -> Result<Outcome<EmailArchiveResults>, ModuleError> {
        let observable = ctx.observable();
        if ctx
            .tree()
            .is_some_and(|tree| tree.this().has_tag(DECRYPTED_EMAIL))
        {
            tracing::warn!("detected decrypted email {observable} as original email");
            return Ok(Outcome::Skipped("a decrypted email".to_owned()));
        }
        let Some(analysis) = ctx
            .dependency_result::<EmailAnalysis>()?
            .filter(|analysis| !analysis.is_tag_only())
        else {
            // scan_inbound_only skips the email analysis of outbound mail on purpose
            if ctx
                .tree()
                .is_some_and(|tree| tree.this().has_tag(ace_mod_email::TAG_OUTBOUND_EMAIL))
            {
                tracing::debug!("outbound email {observable} was not analyzed - not archiving");
            } else {
                tracing::warn!("unable to obtain EmailAnalysis for {observable}");
            }
            return Ok(Outcome::Skipped("no email analysis".to_owned()));
        };
        let email = analysis.email.as_ref();
        // ace3's EmailAnalysis.message_id strips the header's value
        let message_id = email
            .and_then(|e| e.message_id.as_deref())
            .map(|id| id.trim_matches(char::is_whitespace))
            .filter(|id| !id.is_empty());
        let recipients = email.map(|e| e.env_rcpt_to.as_slice()).unwrap_or_default();
        let missing = match message_id {
            None => Some("missing message-id header"),
            Some(_) if recipients.is_empty() => Some("missing envelope recipients"),
            Some(_) => None,
        };
        let (Some(message_id), None) = (message_id, missing) else {
            let missing = missing.unwrap_or_default();
            tracing::error!("unable to archive {observable} - {missing}");
            return Ok(Outcome::Skipped(missing.to_owned()));
        };
        ctx.write::<EmailArchive>(&ArchivedEmailRecord {
            message_id: message_id.to_owned(),
            // ace3 inserts a recipient it can't parse as NULL, which fails and is passed over
            recipients: recipients
                .iter()
                .filter_map(|r| ace_mod_email::py::normalize_email_address(r))
                .collect(),
        })?;
        let hash = observable.value.to_ascii_lowercase();
        let path = archive_path(&hash);
        let summary = format!("Archive Path: {path}");
        let mut result = ResultEnvelope::new(EmailArchiveResults {
            message_id: None,
            // the core gives the archive's id when the archive lands
            archive_id: None,
            archive_path: Some(path),
            hash: Some(hash),
        });
        result.summary = Some(summary);
        Ok(Outcome::Done(result))
    }
}
