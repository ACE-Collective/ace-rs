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
//!
//! For a script holding many Message-IDs (ace3 e7cd8be8): `archived_email_copies` lists every email
//! archived under each, with its hash, when it was last archived, its size and how many have expired,
//! in one query, and writes no row, since it opens nothing; `archived_email_by_hash` reads one of them
//! by its hash, audited as a read by Message-ID is; and `archived_email_download` checks a download of
//! all of them against ace3's caps, `MAX_DOWNLOAD_FILES` emails and `MAX_DOWNLOAD_BYTES` bytes (413
//! past either, 404 when none has an email), and records the download of every email in it in one
//! row, before the API opens them one at a time into its zip. ace3's caps are settings; these are
//! its defaults, fixed, as a cap that can be raised is one more path to filling the API's disk. An
//! email archived before migration 0091 has no recorded size: the lookup reports none, and the cap
//! counts its sealed object's size, which is its gzip's.

use ace_core::email_archive::{
    ArchiveError, Archived, ArchivedCopy, EmailArchive, MAX_LOOKUP_MESSAGE_IDS, copies_of,
    find_by_hash, find_by_message_id,
};
use ace_results::Sha256;
use chrono::{DateTime, Utc};
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

/// The most emails one download holds, ace3's `email_archive.max_bulk_download_files`.
pub const MAX_DOWNLOAD_FILES: usize = 500;
/// The most bytes of emails one download holds, ace3's `max_bulk_download_bytes`.
pub const MAX_DOWNLOAD_BYTES: i64 = 1 << 30;
/// The longest Message-ID taken: RFC 5322's limit on a header line.
const MAX_MESSAGE_ID_CHARS: usize = 998;

/// One requested Message-ID's archived emails, at its index in the request, ace3's
/// `ArchiveLookupResult`.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveLookup {
    pub index: usize,
    /// The Message-ID as the archive stores it, in angle brackets.
    pub message_id: String,
    /// Every email archived under it that the archive still has, newest first.
    pub copies: Vec<EmailCopy>,
    /// How many emails archived under it have expired from the archive.
    pub expired: usize,
}

/// One archived email of a Message-ID.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailCopy {
    /// Its SHA-256, which `archived_email_by_hash` takes.
    pub hash: String,
    pub archived_at: DateTime<Utc>,
    /// Its size, None for one archived before ace-rs recorded it.
    pub size: Option<i64>,
    /// Its sealed object's size, which the download's cap counts when `size` is None.
    object_size: i64,
    /// The row it was last archived in, which a download opens.
    archived: Archived,
}

/// A download, checked against the caps and recorded: each Message-ID's emails, and the ones with
/// none and why (`expired` or `not_archived`, ace3's reasons).
#[derive(Debug, Clone)]
pub struct ArchiveDownload {
    pub found: Vec<ArchiveLookup>,
    pub skipped: Vec<(usize, String, &'static str)>,
}

/// A bulk download's audit row: every email it holds, once each, in request order.
#[derive(Serialize)]
struct ArchivedEmailsDownload<'a> {
    message_ids: usize,
    hashes: &'a [&'a str],
}

impl Recorded for ArchivedEmailsDownload<'_> {}

/// A read by hash's audit row.
#[derive(Serialize)]
struct ArchivedEmailByHash<'a> {
    archive_id: i64,
    hash: &'a str,
}

impl Recorded for ArchivedEmailByHash<'_> {}

/// The Message-IDs of a request, stripped, or why they can't be looked up.
fn message_ids(message_ids: &[String]) -> Result<Vec<String>, ServiceError> {
    if message_ids.is_empty() || message_ids.len() > MAX_LOOKUP_MESSAGE_IDS {
        return Err(ServiceError::InvalidRequest(format!(
            "a lookup names 1 to {MAX_LOOKUP_MESSAGE_IDS} Message-IDs"
        )));
    }
    message_ids
        .iter()
        .map(|id| {
            let id = id.trim();
            if id.is_empty() || id.chars().count() > MAX_MESSAGE_ID_CHARS {
                return Err(ServiceError::InvalidRequest(format!(
                    "a Message-ID is 1 to {MAX_MESSAGE_ID_CHARS} characters"
                )));
            }
            Ok(id.to_owned())
        })
        .collect()
}

/// Each Message-ID's copies, in request order.
fn lookups(
    requested: &[String],
    copies: &std::collections::BTreeMap<String, Vec<ArchivedCopy>>,
) -> Vec<ArchiveLookup> {
    requested
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let message_id = ace_sdk::email_threads::normalize_message_id(id);
            // a Message-ID asked for twice has the same copies twice
            let found = copies.get(&message_id).cloned().unwrap_or_default();
            let expired = found.iter().filter(|copy| !copy.present).count();
            let copies = found
                .into_iter()
                .filter(|copy| copy.present)
                .map(|copy| EmailCopy {
                    archived: Archived {
                        archive_id: copy.archive_id,
                        hash: copy.hash.clone(),
                        object_sha256: copy.object_sha256,
                        insert_date: copy.archived_at,
                    },
                    hash: copy.hash,
                    archived_at: copy.archived_at.and_utc(),
                    size: copy.size,
                    object_size: copy.object_size.unwrap_or_default(),
                })
                .collect();
            ArchiveLookup {
                index,
                message_id,
                copies,
                expired,
            }
        })
        .collect()
}

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

impl Service {
    /// Every email archived under each Message-ID, ace3's `POST /email/archive/lookup`. Needs
    /// `email:read`. It opens nothing, so it writes no audit row.
    pub async fn archived_email_copies(
        &self,
        actor: &Actor,
        requested: &[String],
    ) -> Result<Vec<ArchiveLookup>, ServiceError> {
        let requested = message_ids(requested)?;
        let requested = &requested;
        self.gate
            .read(actor, "archived_email_copies", &EMAIL_READ, &|tx| {
                Box::pin(async move {
                    let copies = copies_of(tx.conn(), requested)
                        .await
                        .map_err(archive_error)?;
                    Ok(lookups(requested, &copies))
                })
            })
            .await
    }

    /// One archived email by its SHA-256, under whichever Message-ID it was archived, ace3's `GET
    /// /email/archive/{sha256}`: the way to read a copy other than the newest. Needs `email:read`, and
    /// records the read.
    pub async fn archived_email_by_hash(
        &self,
        actor: &Actor,
        archive: &EmailArchive,
        hash: &str,
    ) -> Result<ArchivedEmail, ServiceError> {
        let sha256: Sha256 = hash
            .parse()
            .ok()
            .filter(|_| hash.len() == 64 && hash.bytes().all(|b| !b.is_ascii_uppercase()))
            .ok_or_else(|| {
                ServiceError::InvalidRequest("an email's sha256 is 64 lower-case hex digits".into())
            })?;
        let sha256 = &sha256;
        let archived = self
            .gate
            .write(actor, "archived_email_by_hash", &EMAIL_READ, &|tx| {
                Box::pin(async move {
                    no_key(archive)?;
                    let archived = find_by_hash(tx.conn(), sha256)
                        .await
                        .map_err(archive_error)?
                        .ok_or_else(|| {
                            ServiceError::NotFound(format!("no archived email has sha256 {sha256}"))
                        })?;
                    let change = Change::read(
                        Target::archived_email(archived.archive_id),
                        &ArchivedEmailByHash {
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

    /// A download of every email archived under each Message-ID, ace3's `POST /email/archive/download`:
    /// checked against `MAX_DOWNLOAD_FILES` and `MAX_DOWNLOAD_BYTES`, and recorded with every email it
    /// holds. Needs `email:read`. The caller opens each with `open_archived_copy` as it zips them.
    pub async fn archived_email_download(
        &self,
        actor: &Actor,
        archive: &EmailArchive,
        requested: &[String],
    ) -> Result<ArchiveDownload, ServiceError> {
        let requested = message_ids(requested)?;
        let requested = &requested;
        self.gate
            .write(actor, "archived_email_download", &EMAIL_READ, &|tx| {
                Box::pin(async move {
                    no_key(archive)?;
                    let copies = copies_of(tx.conn(), requested)
                        .await
                        .map_err(archive_error)?;
                    let found = lookups(requested, &copies);
                    let members: Vec<&EmailCopy> =
                        found.iter().flat_map(|found| &found.copies).collect();
                    if members.is_empty() {
                        return Err(ServiceError::NotFound(
                            "none of the Message-IDs has an archived email".to_owned(),
                        ));
                    }
                    if members.len() > MAX_DOWNLOAD_FILES {
                        return Err(ServiceError::TooLarge(format!(
                            "{} emails is more than {MAX_DOWNLOAD_FILES}; download fewer Message-IDs at a time",
                            members.len()
                        )));
                    }
                    let bytes: i64 = members
                        .iter()
                        .map(|copy| copy.size.unwrap_or(copy.object_size))
                        .sum();
                    if bytes > MAX_DOWNLOAD_BYTES {
                        return Err(ServiceError::TooLarge(format!(
                            "{bytes} bytes is more than {MAX_DOWNLOAD_BYTES}; download fewer Message-IDs at a time"
                        )));
                    }
                    let (mut hashes, mut rows): (Vec<&str>, Vec<i64>) = (Vec::new(), Vec::new());
                    for copy in &members {
                        if !hashes.contains(&copy.hash.as_str()) {
                            hashes.push(&copy.hash);
                            rows.push(copy.archived.archive_id);
                        }
                    }
                    let change = Change::read(
                        Target::archived_emails(&rows),
                        &ArchivedEmailsDownload {
                            message_ids: requested.len(),
                            hashes: &hashes,
                        },
                    )?;
                    let skipped = found
                        .iter()
                        .filter(|found| found.copies.is_empty())
                        .map(|found| {
                            let why = if found.expired > 0 { "expired" } else { "not_archived" };
                            (found.index, found.message_id.clone(), why)
                        })
                        .collect();
                    let found = found
                        .into_iter()
                        .filter(|found| !found.copies.is_empty())
                        .collect();
                    Ok(Audited::changed(ArchiveDownload { found, skipped }, change))
                })
            })
            .await
    }

    /// The email of a download's copy, opened. The bucket's error when it lost the object since the
    /// download was checked.
    pub async fn open_archived_copy(
        &self,
        archive: &EmailArchive,
        copy: &EmailCopy,
    ) -> Result<Vec<u8>, ServiceError> {
        archive
            .open_archived(&copy.archived)
            .await
            .map_err(archive_error)
    }
}

fn no_key(archive: &EmailArchive) -> Result<(), ServiceError> {
    if archive.config().key.is_none() {
        return Err(ServiceError::Unconfigured(
            "archived emails cannot be decrypted: no encryption key is configured".to_owned(),
        ));
    }
    Ok(())
}

fn archive_error(error: ArchiveError) -> ServiceError {
    match error {
        ArchiveError::Db(e) => e.into(),
        ArchiveError::Bucket(e) => ServiceError::Bucket(e),
        other => ServiceError::Unconfigured(other.to_string()),
    }
}
