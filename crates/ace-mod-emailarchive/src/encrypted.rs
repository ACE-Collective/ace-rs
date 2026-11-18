//! The archived email opener, a port of ace3's `EncryptedArchiveAnalyzer`
//! (`saq/modules/email/archive.py`).
//!
//! For a file whose name ends `.gz.e`, an email as ace3's archive keeps it, it asks the core to
//! decrypt and gunzip it (the `decrypted-archive` read), and adds the email beside it as
//! `<name>.rfc822`, tagged `decrypted_email` and given `type=email` for YARA, as ace3 does. A file
//! that doesn't open, because it isn't one or was sealed with another key, or because the core has
//! no key, gets no result, as ace3 logs it and adds nothing.
//!
//! ace3 also leaves the decrypted gzip, `<name>.rfc822.gz`, in the alert's directory, not added as
//! an observable. ace4 keeps no file outside the tree, so there's none.

use ace_results::types::email_archive::EncryptedArchiveAnalysis;
use ace_results::{AlertPath, NewFile, ObservableKind, ResultEnvelope, Sha256, YaraMeta};
use ace_sdk::reads::{DecryptedArchive, DecryptedArchiveRequest, Read, ReadKind};
use ace_sdk::takes::{Case, Condition, Takes, Text};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};

use crate::DECRYPTED_EMAIL;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<EncryptedArchiveAnalyzer>();

/// The end of an archived email's name.
pub const SEALED_SUFFIX: &str = ".gz.e";

/// The archived email opener.
pub struct EncryptedArchiveAnalyzer;

impl Module for EncryptedArchiveAnalyzer {
    const NAME: &'static str = "encrypted_archive_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const READS: &'static [Read] = &[DecryptedArchive::READ];
    type Output = EncryptedArchiveAnalysis;
    type Settings = ();

    fn init(_settings: &()) -> Result<Self, ModuleError> {
        Ok(EncryptedArchiveAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        Takes::everything().and(
            Condition::Path(Text::ends_with(SEALED_SUFFIX, Case::Exact)),
            "not an archived email",
        )
    }
}

impl Lookup for EncryptedArchiveAnalyzer {
    /// It talks only to the lease API, which every pool may reach.
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<EncryptedArchiveAnalysis>, ModuleError> {
        // a lookup gets the file's path, not its bytes, which the core opens
        let Some(input) = ctx.observable().path.as_ref() else {
            return Err(ModuleError::other(format!(
                "{} is not a file observable",
                ctx.observable()
            )));
        };
        // `takes` declined any other path
        let Some(stem) = input.as_str().strip_suffix(SEALED_SUFFIX) else {
            return Ok(Outcome::Skipped("not an archived email".to_owned()));
        };
        let answer = ctx
            .read::<DecryptedArchive>(&DecryptedArchiveRequest::default())
            .await?;
        let Some(email) = answer.email else {
            tracing::error!(
                "unable to decrypt {input}: {}",
                answer.error.as_deref().unwrap_or("no answer")
            );
            return Ok(Outcome::Skipped("didn't decrypt".to_owned()));
        };
        let path = AlertPath::new(format!("{stem}.rfc822")).map_err(ModuleError::other)?;
        let sha256: Sha256 = email.sha256.parse().map_err(ModuleError::other)?;
        let mut file = NewFile::new(path.clone(), sha256, email.size);
        file.add_tag(DECRYPTED_EMAIL);
        file.yara_meta
            .push(YaraMeta::new("type", "email").map_err(ModuleError::other)?);
        // ace3 names it from the root's storage directory, whose files are under `files/`
        let decrypted_file = format!("files/{}", path.as_str());
        let mut result = ResultEnvelope::new(EncryptedArchiveAnalysis {
            decrypted_file: Some(decrypted_file.clone()),
        });
        result.summary = Some(format!(
            "Encrypted Archive Analysis - retrieved {decrypted_file}"
        ));
        result.files.push(file);
        Ok(Outcome::Done(result))
    }
}
