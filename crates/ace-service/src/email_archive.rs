//! The email archive's router (PLAN.md 7.5 batch 9): ace3's `email` router, which serves an archived
//! email, decrypted, by its Message-ID (`aceapi_v2/email/`).
//!
//! The archive holds every email the archiver kept, from any alert, in the clear once opened, so
//! reading one needs `email:read`, ace3's name, and each read that finds an email writes an audit
//! row naming what was read: the Message-ID, the archive's row and the email's hash. ace3 logs no
//! audit for it; here a read of an alert's file is audited as a download is (`Change::read`), and this
//! is the same. A Message-ID the archive doesn't have writes no row: nothing was read.
//!
//! The core holds the key (`ace_core::email_archive`): without one this refuses after the permission
//! check, as ace3 answers 500 when its node has no key. The email is opened after the row is written,
//! so a failure to open it, such as an object the bucket lost, is an error with the read recorded.

use ace_core::email_archive::{ArchiveError, EmailArchive, find_by_message_id};
use serde::Serialize;

use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::EMAIL_READ;
use crate::{Actor, Service, ServiceError};

/// An archived email, opened.
#[derive(Debug, Clone)]
pub struct ArchivedEmail {
    pub archive_id: i64,
    /// The SHA-256 of its bytes.
    pub hash: String,
    pub bytes: Vec<u8>,
}

/// A read's audit row.
#[derive(Serialize)]
struct ArchivedEmailRead<'a> {
    message_id: &'a str,
    archive_id: i64,
    hash: &'a str,
}

impl Recorded for ArchivedEmailRead<'_> {}

impl Service {
    /// The newest archived email with this Message-ID, as ace3's `get_archived_email`, decrypted. Needs
    /// `email:read`, and records the read.
    pub async fn archived_email(
        &self,
        actor: &Actor,
        archive: &EmailArchive,
        message_id: &str,
    ) -> Result<ArchivedEmail, ServiceError> {
        let archived = self
            .gate
            .write(actor, "archived_email", &EMAIL_READ, &|tx| {
                Box::pin(async move {
                    if archive.config().key.is_none() {
                        return Err(ServiceError::Unconfigured(
                            "archived emails cannot be decrypted: no encryption key is configured"
                                .to_owned(),
                        ));
                    }
                    let archived = find_by_message_id(tx.conn(), message_id)
                        .await
                        .map_err(archive_error)?
                        .ok_or_else(|| {
                            ServiceError::NotFound(format!(
                                "no archived email has message id {message_id}"
                            ))
                        })?;
                    let change = Change::read(
                        Target::archived_email(archived.archive_id),
                        &ArchivedEmailRead {
                            message_id,
                            archive_id: archived.archive_id,
                            hash: &archived.hash,
                        },
                    )?;
                    Ok(Audited::changed(archived, change))
                })
            })
            .await?;
        let bytes = archive
            .open_archived(&archived)
            .await
            .map_err(archive_error)?;
        Ok(ArchivedEmail {
            archive_id: archived.archive_id,
            hash: archived.hash,
            bytes,
        })
    }
}

fn archive_error(error: ArchiveError) -> ServiceError {
    match error {
        ArchiveError::Db(e) => e.into(),
        ArchiveError::Bucket(e) => ServiceError::Bucket(e),
        other => ServiceError::Unconfigured(other.to_string()),
    }
}
