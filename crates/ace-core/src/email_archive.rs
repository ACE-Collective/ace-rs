//! The email archive (PLAN.md 7.5 batch 9): ace3's `saq/email_archive/`, which keeps every email its
//! `email_archiver` module archives, encrypted, findable by its Message-ID, for
//! `message_id_analyzer_v2` to pull back into another alert and the `email` API router to serve.
//!
//! **Where it lives.** An archived email is one object in the bucket's `email_archive` pool: the
//! email's bytes gzipped and then encrypted with ACE's key (`seal`). One table finds it, as ace3's
//! `archived_messages` does since its 4f1fa192: each row of `email_archive.archive` (migration 0041,
//! cut down by 0079) is the SHA-256 of a normalized Message-ID, the SHA-256 of the email's bytes
//! (ace3's digest), the object and when it was archived. ace3 dropped its URL index, its
//! `email_history` and its `archive_server` registration, and ace-rs dropped the first two with it; one
//! bucket is every node's here, so there never was a server.
//!
//! **How it's encrypted.** AES-256-GCM, as ace3's `saq.crypto`, under a 32-byte key the core reads
//! from `ACE_RS_ENCRYPTION_KEY` (64 hex digits) and nothing else holds: workers never see it, since
//! the core seals and opens for them (`reads.md`). The core writes ace3's `v1` layout, `ACE-GCM`, a
//! version byte, an 8-byte key id, the plaintext's size and the nonce, all authenticated, with the
//! tag at the end, and reads only that. Nothing is released before the tag verifies. Without a key
//! the core archives and opens nothing, and says so.
//!
//! **Bounds.** ace3 streams and sets no size limit. Here sealing and opening are in memory, so an
//! email is archived and opened only up to `MAX_EMAIL_BYTES`, and a gunzip stops past it.
//!
//! **Retention.** ace3's weekly partitions: `email_archive_partitions` (the scheduler) drops a week
//! once its newest row is past `retention_days`, and makes the weeks ahead (`partitions`). An
//! archive's object is held by its row (`Hold`, kind `email_archive`) until its week is dropped, and
//! the bucket's GC removes it after the pool's grace.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

use ace_results::{ObservableKind, Sha256};
use ace_sdk::email_threads::normalize_message_id;
use ace_sdk::writes::ArchivedEmailRecord;
use ace_store::Spooled;
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit};
use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDate, NaiveDateTime, Utc};
use sha2::{Digest, Sha256 as Sha256Hasher};
use uuid::Uuid;

use crate::bucket::{ALERT_FILES, Bucket, BucketError, Hold};
use crate::db::{Db, DbError, Tx};
use crate::queue::Task;

pub mod partitions;

/// The bucket's pool for archived emails.
pub const EMAIL_ARCHIVE: &str = "email_archive";
/// The largest email the core archives or opens, and the most a gunzip writes.
pub const MAX_EMAIL_BYTES: u64 = 64 * 1024 * 1024;
/// The kind of the hold an archive's row keeps on its object.
pub const HOLD_KIND: &str = "email_archive";

const MAGIC: &[u8] = b"ACE-GCM";
const FORMAT_V1: u8 = 1;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_ID_SIZE: usize = 8;
const V1_HEADER: usize = MAGIC.len() + 1 + KEY_ID_SIZE + 8 + NONCE_SIZE;

/// ACE's encryption key: 32 bytes, which only the core holds.
#[derive(Clone)]
pub struct ArchiveKey(Arc<[u8; 32]>);

impl std::fmt::Debug for ArchiveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ArchiveKey(id {})", hex::encode(self.id()))
    }
}

impl ArchiveKey {
    pub fn new(key: [u8; 32]) -> Self {
        ArchiveKey(Arc::new(key))
    }

    /// The key from 64 hex digits.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let bytes =
            hex::decode(text.trim()).map_err(|e| format!("the encryption key isn't hex: {e}"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| format!("the encryption key is {} bytes, not 32", b.len()))?;
        Ok(ArchiveKey::new(key))
    }

    /// ace3's key id: the first 8 bytes of SHA-256 of `ace-key-id:` and the key, which identifies it
    /// without revealing it.
    pub fn id(&self) -> [u8; KEY_ID_SIZE] {
        let digest = Sha256Hasher::new()
            .chain_update(b"ace-key-id:")
            .chain_update(self.0.as_slice())
            .finalize();
        let mut id = [0; KEY_ID_SIZE];
        id.copy_from_slice(&digest[..KEY_ID_SIZE]);
        id
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(self.0.as_ref().into())
    }
}

/// The archive's settings: `ACE_RS_ENCRYPTION_KEY`, and ace3's `email_archive.partition_retention_days`
/// in `ACE_RS_EMAIL_ARCHIVE_RETENTION_DAYS`, 30 by default.
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    pub key: Option<ArchiveKey>,
    pub retention_days: u32,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        ArchiveConfig {
            key: None,
            retention_days: 30,
        }
    }
}

impl ArchiveConfig {
    pub fn from_env() -> Result<Self, String> {
        let mut config = ArchiveConfig::default();
        if let Some(key) = std::env::var("ACE_RS_ENCRYPTION_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())
        {
            config.key = Some(ArchiveKey::from_hex(&key)?);
        }
        let var = "ACE_RS_EMAIL_ARCHIVE_RETENTION_DAYS";
        if let Ok(days) = std::env::var(var) {
            config.retention_days = days
                .parse::<u32>()
                .ok()
                .filter(|d| *d > 0)
                .ok_or_else(|| format!("{var} must be a whole number of days, not {days:?}"))?;
        }
        Ok(config)
    }

    pub fn with_key(mut self, key: ArchiveKey) -> Self {
        self.key = Some(key);
        self
    }
}

/// Why the archive couldn't do something.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error(
        "the core has no encryption key (ACE_RS_ENCRYPTION_KEY), so it can't archive or open an email"
    )]
    NoKey,
    #[error("{0} is larger than the {MAX_EMAIL_BYTES} bytes the core archives or opens")]
    TooLarge(String),
    #[error("{0}")]
    Crypto(String),
    #[error(transparent)]
    Bucket(#[from] BucketError),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for ArchiveError {
    fn from(error: sqlx::Error) -> Self {
        ArchiveError::Db(DbError::Sqlx(error))
    }
}

// ---- encryption ----

/// Encrypts `plaintext` in ace3's `v1` layout.
pub fn encrypt(key: &ArchiveKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|e| format!("no randomness for a nonce: {e}"))?;
    let mut header = Vec::with_capacity(V1_HEADER);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_V1);
    header.extend_from_slice(&key.id());
    header.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    header.extend_from_slice(&nonce);
    let mut body = plaintext.to_vec();
    let tag = key
        .cipher()
        .encrypt_inout_detached((&nonce).into(), &header, body.as_mut_slice().into())
        .map_err(|e| format!("encrypting: {e}"))?;
    let mut out = header;
    out.extend_from_slice(&body);
    out.extend_from_slice(tag.as_slice());
    Ok(out)
}

/// Decrypts ace3's `v1` layout. Nothing is returned unless the tag verifies.
pub fn decrypt(key: &ArchiveKey, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() <= MAGIC.len() || !data.starts_with(MAGIC) {
        return Err("not an encrypted file in the v1 layout".to_owned());
    }
    let version = data[MAGIC.len()];
    if version != FORMAT_V1 {
        return Err(format!(
            "unsupported encrypted file format version {version}"
        ));
    }
    if data.len() < V1_HEADER {
        return Err("encrypted data is truncated (shorter than a v1 header)".to_owned());
    }
    let key_id = &data[MAGIC.len() + 1..MAGIC.len() + 1 + KEY_ID_SIZE];
    if key_id != key.id() {
        return Err(format!(
            "data was encrypted with key {} but the loaded key is {}",
            hex::encode(key_id),
            hex::encode(key.id())
        ));
    }
    let size_at = MAGIC.len() + 1 + KEY_ID_SIZE;
    let expected_size = u64::from_le_bytes(data[size_at..size_at + 8].try_into().expect("8 bytes"));
    if data.len() < V1_HEADER + TAG_SIZE {
        return Err("encrypted data is truncated (no authentication tag)".to_owned());
    }
    let nonce: [u8; NONCE_SIZE] = data[V1_HEADER - NONCE_SIZE..V1_HEADER]
        .try_into()
        .expect("12 bytes");
    let tag_at = data.len() - TAG_SIZE;
    let tag: [u8; TAG_SIZE] = data[tag_at..].try_into().expect("16 bytes");
    let mut body = data[V1_HEADER..tag_at].to_vec();
    key.cipher()
        .decrypt_inout_detached(
            (&nonce).into(),
            &data[..V1_HEADER],
            body.as_mut_slice().into(),
            (&tag).into(),
        )
        .map_err(|_| "authentication tag verification failed".to_owned())?;
    if expected_size != body.len() as u64 {
        return Err(format!(
            "decrypted {} bytes but the header says {expected_size}",
            body.len()
        ));
    }
    Ok(body)
}

/// Gzips `bytes`, as ace3's `gzip.open(..., "wb")`.
pub fn gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(9));
    encoder
        .write_all(bytes)
        .and_then(|()| encoder.finish())
        .map_err(|e| format!("gzipping: {e}"))
}

/// Gunzips `bytes`, every member as Python's `gzip` reads them, failing past `max` bytes out.
pub fn gunzip(bytes: &[u8], max: u64) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(bytes)
        .take(max + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("gunzipping: {e}"))?;
    if out.len() as u64 > max {
        return Err(format!("the email gunzips to more than {max} bytes"));
    }
    Ok(out)
}

/// An email as the archive keeps it: gzipped, then encrypted.
pub fn seal(key: &ArchiveKey, email: &[u8]) -> Result<Vec<u8>, String> {
    encrypt(key, &gzip(email)?)
}

/// An archived email's bytes: decrypted, then gunzipped, up to `MAX_EMAIL_BYTES`.
pub fn open(key: &ArchiveKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    gunzip(&decrypt(key, sealed)?, MAX_EMAIL_BYTES)
}

/// ace3's `UNHEX(SHA2(value, 256))`.
pub fn value_hash(value: &str) -> Vec<u8> {
    Sha256Hasher::digest(value.as_bytes()).to_vec()
}

/// The ISO week `at` falls in: its Monday, and the next.
pub fn week_of(at: NaiveDateTime) -> (NaiveDateTime, NaiveDateTime) {
    let date = at.date();
    let monday = date - ChronoDuration::days(i64::from(date.weekday().num_days_from_monday()));
    let start = monday.and_hms_opt(0, 0, 0).expect("midnight");
    (start, start + ChronoDuration::days(7))
}

/// When an archive's row goes: the end of its week, past `retention_days`, which is when
/// maintenance drops the week.
pub fn kept_until(insert_date: NaiveDateTime, retention_days: u32) -> DateTime<Utc> {
    let (_, end) = week_of(insert_date);
    (end + ChronoDuration::days(i64::from(retention_days))).and_utc()
}

/// An archived email the archive found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archived {
    pub archive_id: i64,
    /// The email's SHA-256, lower-case hex.
    pub hash: String,
    pub object_sha256: String,
    pub insert_date: NaiveDateTime,
}

/// What an `email-archive` write keeps, checked and sealed before the end's transaction.
#[derive(Debug, Clone)]
pub struct Prepared {
    hash: Vec<u8>,
    /// The email's size, when it's known: an object archived before migration 0091 has none.
    size: Option<i64>,
    object: PreparedObject,
    message_id: String,
    root: Uuid,
    observable: i64,
}

#[derive(Debug, Clone)]
enum PreparedObject {
    /// The email is archived already, in this object, which a new row holds too: ace3 keeps one file
    /// for each email's hash.
    Existing(Sha256),
    /// The email, sealed now.
    New(Arc<Spooled>),
}

/// The archive: the database, the bucket and the key.
#[derive(Debug, Clone)]
pub struct EmailArchive {
    db: Db,
    bucket: Bucket,
    config: ArchiveConfig,
}

impl EmailArchive {
    pub fn new(db: Db, bucket: Bucket, config: ArchiveConfig) -> Self {
        EmailArchive { db, bucket, config }
    }

    pub fn config(&self) -> &ArchiveConfig {
        &self.config
    }

    fn key(&self) -> Result<&ArchiveKey, ArchiveError> {
        self.config.key.as_ref().ok_or(ArchiveError::NoKey)
    }

    /// The object's bytes, up to `MAX_EMAIL_BYTES`.
    async fn bytes(&self, pool: &str, sha256: &Sha256) -> Result<Vec<u8>, ArchiveError> {
        let Some(object) = self.bucket.object(pool, sha256).await? else {
            return Err(BucketError::NotFound {
                pool: pool.to_owned(),
                sha256: *sha256,
            }
            .into());
        };
        // a sealed email is a little larger than its gzip, which can be larger than the email
        if object.size > MAX_EMAIL_BYTES + MAX_EMAIL_BYTES / 16 + 1024 {
            return Err(ArchiveError::TooLarge(format!(
                "{pool}/{sha256} ({} bytes)",
                object.size
            )));
        }
        let cached = self.bucket.get(pool, sha256).await?;
        let mut file = tokio::fs::File::from_std(cached.file);
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file, &mut bytes)
            .await
            .map_err(|e| ArchiveError::Bucket(BucketError::Store(e.into())))?;
        Ok(bytes)
    }

    /// Opens a sealed object, decrypting on a blocking thread.
    async fn open_bytes(&self, sealed: Vec<u8>) -> Result<Vec<u8>, ArchiveError> {
        let key = self.key()?.clone();
        tokio::task::spawn_blocking(move || open(&key, &sealed))
            .await
            .map_err(|e| ArchiveError::Crypto(format!("the decryption stopped: {e}")))?
            .map_err(ArchiveError::Crypto)
    }

    // ---- the write ----

    /// Checks and seals an `email-archive` write for `task`, before the end's transaction. The
    /// task's observable must be a file with a parsed email in the root, whose Message-ID is the
    /// write's, as ace3's module reads it from the email's analysis.
    pub async fn prepare(
        &self,
        task: &Task,
        email_message_id: Option<&str>,
        record: ArchivedEmailRecord,
    ) -> Result<Prepared, PrepareFailure> {
        if task.observable.kind != ObservableKind::File {
            return Err(PrepareFailure::Refused(format!(
                "email-archive archives a file, and task {}'s observable is a {}",
                task.id, task.observable.kind
            )));
        }
        if email_message_id.map(str::trim) != Some(record.message_id.trim()) {
            return Err(PrepareFailure::Refused(format!(
                "email-archive names the Message-ID {:?}, which isn't the task's email's",
                record.message_id
            )));
        }
        let sha256: Sha256 = task.observable.value.parse().map_err(|_| {
            PrepareFailure::Refused(format!(
                "task {}'s file {:?} isn't named by a sha256",
                task.id, task.observable.value
            ))
        })?;
        let key = self
            .key()
            .map_err(|e| PrepareFailure::Refused(e.to_string()))?;
        let hash = sha256.0.to_vec();
        let existing = sqlx::query!(
            r#"SELECT a.object_sha256, a.size FROM email_archive.archive a
               JOIN store.objects o ON o.pool = $2 AND o.sha256 = a.object_sha256
               WHERE a.hash = $1 AND o.state = 'present'
               ORDER BY a.insert_date DESC LIMIT 1"#,
            &hash,
            EMAIL_ARCHIVE,
        )
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| PrepareFailure::Failed(ArchiveError::from(e)))?;
        let existing =
            existing.and_then(|row| Some((row.object_sha256.parse::<Sha256>().ok()?, row.size)));
        let (object, size) = match existing {
            Some((object, size)) => (PreparedObject::Existing(object), size),
            None => {
                let email = self
                    .bytes(ALERT_FILES, &sha256)
                    .await
                    .map_err(|e| match e {
                        ArchiveError::TooLarge(why) => {
                            PrepareFailure::Refused(ArchiveError::TooLarge(why).to_string())
                        }
                        other => PrepareFailure::Failed(other),
                    })?;
                let key = key.clone();
                let size = i64::try_from(email.len()).ok();
                let sealed = tokio::task::spawn_blocking(move || seal(&key, &email))
                    .await
                    .map_err(|e| {
                        PrepareFailure::Failed(ArchiveError::Crypto(format!(
                            "the encryption stopped: {e}"
                        )))
                    })?
                    .map_err(|e| PrepareFailure::Failed(ArchiveError::Crypto(e)))?;
                let spooled = self
                    .bucket
                    .store()
                    .spool_bytes(&sealed)
                    .await
                    .map_err(|e| PrepareFailure::Failed(BucketError::from(e).into()))?;
                (PreparedObject::New(Arc::new(spooled)), size)
            }
        };
        Ok(Prepared {
            hash,
            size,
            object,
            message_id: normalize_message_id(&record.message_id),
            root: task.root,
            observable: task.observable.id.0,
        })
    }

    /// Lands a prepared archive in the end's transaction, as ace3's `archive_email`: the object held
    /// by its row until the row goes, and the row, its normalized Message-ID to the email. A row of
    /// the same Message-ID and email in the same second is the row that's there, as ace3's
    /// `INSERT IGNORE`.
    pub async fn land(&self, tx: &mut Tx<'_>, prepared: &Prepared) -> Result<(), ArchiveError> {
        let object_sha256 = match &prepared.object {
            PreparedObject::Existing(object) => *object,
            PreparedObject::New(spooled) => spooled.sha256,
        };
        let inserted = sqlx::query!(
            r#"INSERT INTO email_archive.archive
                   (message_id_hash, hash, object_sha256, insert_date, root_id, observable_id, size)
               VALUES ($1, $2, $3, date_trunc('second', now() AT TIME ZONE 'UTC'), $4, $5, $6)
               ON CONFLICT (message_id_hash, hash, insert_date) DO NOTHING
               RETURNING archive_id, insert_date"#,
            value_hash(&prepared.message_id),
            &prepared.hash,
            object_sha256.to_hex(),
            prepared.root,
            prepared.observable,
            prepared.size,
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some(row) = inserted else {
            tracing::info!(
                hash = %hex::encode(&prepared.hash),
                write = "email-archive",
                "the email is archived under its Message-ID this second already"
            );
            return Ok(());
        };
        let hold = Hold::new(HOLD_KIND, row.archive_id.to_string())
            .until(kept_until(row.insert_date, self.config.retention_days));
        match &prepared.object {
            PreparedObject::Existing(object) => {
                self.bucket
                    .hold_in(tx, EMAIL_ARCHIVE, object, &hold)
                    .await?
            }
            PreparedObject::New(spooled) => {
                self.bucket
                    .put_in(tx, EMAIL_ARCHIVE, spooled, Some(&hold))
                    .await?;
            }
        }
        tracing::info!(
            archive_id = row.archive_id,
            hash = %hex::encode(&prepared.hash),
            object = %object_sha256,
            write = "email-archive",
            "archived an email"
        );
        Ok(())
    }

    // ---- the reads ----

    /// The newest archived email with this Message-ID whose object the bucket still has, as ace3's
    /// `find_archived_email`.
    pub async fn find_by_message_id(
        &self,
        message_id: &str,
    ) -> Result<Option<Archived>, ArchiveError> {
        find_by_message_id(self.db.pool(), message_id).await
    }

    /// The email in an archive's object, decrypted and gunzipped.
    pub async fn open_archived(&self, archived: &Archived) -> Result<Vec<u8>, ArchiveError> {
        self.key()?;
        let object: Sha256 = archived.object_sha256.parse().map_err(|_| {
            ArchiveError::Crypto(format!(
                "archive {} names no object: {:?}",
                archived.archive_id, archived.object_sha256
            ))
        })?;
        let sealed = self.bytes(EMAIL_ARCHIVE, &object).await?;
        self.open_bytes(sealed).await
    }

    /// Puts an opened email in the root's files, held by the root, as a module's own output is.
    pub async fn put_in_root(
        &self,
        root: Uuid,
        email: &[u8],
    ) -> Result<ace_sdk::reads::ReadFile, ArchiveError> {
        let put = self
            .bucket
            .put_bytes(ALERT_FILES, email, Some(&Hold::root(root)))
            .await?;
        Ok(ace_sdk::reads::ReadFile {
            sha256: put.object.sha256.to_hex(),
            size: put.object.size,
        })
    }
}

/// An email to archive as of a given time, for tests and fixtures (`EmailArchive::seed`).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone)]
pub struct Seed<'a> {
    pub email: &'a [u8],
    pub message_id: &'a str,
    pub insert_date: NaiveDateTime,
}

#[cfg(any(test, feature = "testing"))]
impl EmailArchive {
    /// Archives `seed` as the archiver's write would have at its `insert_date`, from a root and file
    /// that needn't exist: sealed with the key, held by its row, under its Message-ID. Returns the
    /// archive's id and its object's sha256.
    pub async fn seed(&self, seed: &Seed<'_>) -> Result<(i64, Sha256), ArchiveError> {
        // checked when it runs, not when it builds: the offline query data is the crate's own build's,
        // which hasn't this feature
        let key = self.key()?.clone();
        let sealed = seal(&key, seed.email).map_err(ArchiveError::Crypto)?;
        let spooled = self
            .bucket
            .store()
            .spool_bytes(&sealed)
            .await
            .map_err(BucketError::from)?;
        let hash = Sha256Hasher::digest(seed.email).to_vec();
        let mut tx = self.db.begin().await?;
        let archive_id: i64 = sqlx::query_scalar(
            "INSERT INTO email_archive.archive
                 (message_id_hash, hash, object_sha256, insert_date, root_id, observable_id, size)
             VALUES ($1, $2, $3, $4, $5, 0, $6) RETURNING archive_id",
        )
        .bind(value_hash(&normalize_message_id(seed.message_id)))
        .bind(&hash)
        .bind(spooled.sha256.to_hex())
        .bind(seed.insert_date)
        .bind(Uuid::nil())
        .bind(i64::try_from(seed.email.len()).ok())
        .fetch_one(tx.conn())
        .await?;
        let hold = Hold::new(HOLD_KIND, archive_id.to_string())
            .until(kept_until(seed.insert_date, self.config.retention_days));
        self.bucket
            .put_in(&mut tx, EMAIL_ARCHIVE, &spooled, Some(&hold))
            .await?;
        tx.commit().await?;
        Ok((archive_id, spooled.sha256))
    }
}

/// Why an `email-archive` write wasn't prepared.
#[derive(Debug)]
pub enum PrepareFailure {
    /// The write is wrong, or the core can't archive it, and would be on any attempt: the task fails.
    Refused(String),
    /// The database or the bucket failed.
    Failed(ArchiveError),
}

/// The newest archived email with this Message-ID, normalized, whose object the bucket still has, as
/// ace3's `find_archived_email`: its rows newest first (`ORDER BY insert_date DESC`), the first whose
/// email the pool has. A row outlives its object only when the object is gone some other way, since
/// the row holds it.
pub async fn find_by_message_id<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    message_id: &str,
) -> Result<Option<Archived>, ArchiveError> {
    let row = sqlx::query!(
        r#"SELECT a.archive_id, a.hash, a.object_sha256, a.insert_date
           FROM email_archive.archive a
           JOIN store.objects o ON o.pool = $2 AND o.sha256 = a.object_sha256
           WHERE a.message_id_hash = $1 AND o.state = 'present'
           ORDER BY a.insert_date DESC, a.archive_id DESC LIMIT 1"#,
        value_hash(&normalize_message_id(message_id)),
        EMAIL_ARCHIVE,
    )
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|row| Archived {
        archive_id: row.archive_id,
        hash: hex::encode(row.hash),
        object_sha256: row.object_sha256,
        insert_date: row.insert_date,
    }))
}

/// One email archived under a Message-ID, ace3's `ArchivedCopy` with its pool's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedCopy {
    /// Its newest row under the Message-ID.
    pub archive_id: i64,
    pub object_sha256: String,
    /// The email's SHA-256, lower-case hex: what `find_by_hash` takes.
    pub hash: String,
    /// The last time it was archived under that Message-ID, UTC.
    pub archived_at: NaiveDateTime,
    /// The email's size, None for one archived before migration 0091.
    pub size: Option<i64>,
    /// The sealed object's size in the bucket.
    pub object_size: Option<i64>,
    /// Whether the bucket still has it; one that hasn't has expired.
    pub present: bool,
}

/// The most Message-IDs one lookup takes, ace3's `MAX_MESSAGE_IDS`.
pub const MAX_LOOKUP_MESSAGE_IDS: usize = 1000;

/// Every email archived under each of `message_ids` that still has a row, by its normalized
/// Message-ID, newest first, each email once at the last time it was archived, as ace3's
/// `query_archived_copies`, with whether the bucket still has it, as its pool's `sizes`. One query for
/// all of them, which `MAX_LOOKUP_MESSAGE_IDS` bounds; a Message-ID with no rows is left out.
pub async fn copies_of<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    message_ids: &[String],
) -> Result<BTreeMap<String, Vec<ArchivedCopy>>, ArchiveError> {
    let normalized: Vec<String> = message_ids
        .iter()
        .map(|m| normalize_message_id(m))
        .collect();
    let hashes: Vec<Vec<u8>> = normalized.iter().map(|m| value_hash(m)).collect();
    let rows = sqlx::query!(
        r#"SELECT w.message_id AS "message_id!", a.archive_id, a.object_sha256, a.hash,
                  a.insert_date, a.size,
                  o.size AS "object_size?", coalesce(o.state = 'present', false) AS "present!"
           FROM (SELECT DISTINCT * FROM unnest($1::text[], $2::bytea[]) AS w(message_id, message_id_hash)) w
           JOIN email_archive.archive a ON a.message_id_hash = w.message_id_hash
           LEFT JOIN store.objects o ON o.pool = $3 AND o.sha256 = a.object_sha256
           ORDER BY w.message_id, a.insert_date DESC, a.archive_id DESC"#,
        &normalized,
        &hashes,
        EMAIL_ARCHIVE,
    )
    .fetch_all(executor)
    .await?;
    let mut copies: BTreeMap<String, Vec<ArchivedCopy>> = BTreeMap::new();
    for row in rows {
        let hash = hex::encode(&row.hash);
        let found = copies.entry(row.message_id).or_default();
        // newest first, so an email's first row is the last time it was archived
        if found.iter().any(|copy| copy.hash == hash) {
            continue;
        }
        found.push(ArchivedCopy {
            archive_id: row.archive_id,
            object_sha256: row.object_sha256,
            hash,
            archived_at: row.insert_date,
            size: row.size,
            object_size: row.object_size,
            present: row.present,
        });
    }
    Ok(copies)
}

/// The newest row of the email whose SHA-256 is `hash` whose object the bucket still has, under any
/// Message-ID: ace3's `open_archived_copy` reads an email by its digest.
pub async fn find_by_hash<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    hash: &Sha256,
) -> Result<Option<Archived>, ArchiveError> {
    let row = sqlx::query!(
        r#"SELECT a.archive_id, a.hash, a.object_sha256, a.insert_date
           FROM email_archive.archive a
           JOIN store.objects o ON o.pool = $2 AND o.sha256 = a.object_sha256
           WHERE a.hash = $1 AND o.state = 'present'
           ORDER BY a.insert_date DESC, a.archive_id DESC LIMIT 1"#,
        hash.0.as_slice(),
        EMAIL_ARCHIVE,
    )
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|row| Archived {
        archive_id: row.archive_id,
        hash: hex::encode(row.hash),
        object_sha256: row.object_sha256,
        insert_date: row.insert_date,
    }))
}

/// The first day of ISO week `week` of `year`.
pub fn iso_week_start(year: i32, week: u32) -> Option<NaiveDateTime> {
    NaiveDate::from_isoywd_opt(year, week, chrono::Weekday::Mon)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ArchiveKey {
        ArchiveKey::new([7; 32])
    }

    #[test]
    fn a_sealed_email_opens_with_its_key_and_no_other() {
        let sealed = seal(&key(), b"From: a@b\r\n\r\nbody").expect("seals");
        assert!(sealed.starts_with(b"ACE-GCM\x01"));
        assert_eq!(
            open(&key(), &sealed).expect("opens"),
            b"From: a@b\r\n\r\nbody"
        );
        let other = ArchiveKey::new([8; 32]);
        assert!(
            open(&other, &sealed)
                .unwrap_err()
                .contains("encrypted with key")
        );
    }

    #[test]
    fn a_changed_byte_fails_the_tag_and_releases_nothing() {
        let mut sealed = encrypt(&key(), b"secret").expect("encrypts");
        let last = sealed.len() - 20;
        sealed[last] ^= 1;
        assert_eq!(
            decrypt(&key(), &sealed).unwrap_err(),
            "authentication tag verification failed"
        );
        // the header is authenticated too
        let mut sealed = encrypt(&key(), b"secret").expect("encrypts");
        sealed[MAGIC.len() + 1 + KEY_ID_SIZE] ^= 1;
        assert!(decrypt(&key(), &sealed).is_err());
    }

    #[test]
    fn truncated_data_says_so() {
        assert!(decrypt(&key(), b"short").unwrap_err().contains("v1 layout"));
        assert!(
            decrypt(&key(), b"ACE-GCM\x01abc")
                .unwrap_err()
                .contains("truncated")
        );
        assert!(
            decrypt(&key(), b"ACE-GCM\x02abcdefghijklmnopqrstuvwxyz0123456789")
                .unwrap_err()
                .contains("version 2")
        );
    }

    #[test]
    fn a_gunzip_stops_past_its_bound() {
        let zipped = gzip(&vec![b'a'; 10_000]).expect("gzips");
        assert_eq!(gunzip(&zipped, 10_000).expect("fits").len(), 10_000);
        assert!(
            gunzip(&zipped, 9_999)
                .unwrap_err()
                .contains("more than 9999")
        );
    }

    #[test]
    fn a_key_reads_from_64_hex_digits_only() {
        assert!(ArchiveKey::from_hex(&"ab".repeat(32)).is_ok());
        assert!(
            ArchiveKey::from_hex("abcd")
                .unwrap_err()
                .contains("2 bytes")
        );
        assert!(ArchiveKey::from_hex(&"zz".repeat(32)).is_err());
        assert!(!format!("{:?}", key()).contains("0707"));
    }

    #[test]
    fn a_sealed_gzip_bomb_stops_at_the_bound() {
        // 80 MiB of zeros gzips to about 80 KiB
        let bomb = encrypt(&key(), &gzip(&vec![0; 80 << 20]).expect("gzips")).expect("seals");
        assert!(bomb.len() < 1 << 20);
        assert!(
            open(&key(), &bomb)
                .unwrap_err()
                .contains("more than 67108864")
        );
    }

    /// docs/measurements/email-archive.md: what crafted archives cost the core to open, five runs
    /// each. `cargo test -p ace-core --lib measure_open -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn measure_open() {
        // bytes that don't compress, so the sealed copy is as large as the email
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let email: Vec<u8> = (0..MAX_EMAIL_BYTES)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let sealed = seal(&key(), &email).expect("seals");
        let mut tampered = sealed.clone();
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        let over = seal(&key(), &[email.as_slice(), b"x"].concat()).expect("seals");
        let bomb = encrypt(&key(), &gzip(&vec![0; 1 << 30]).expect("gzips")).expect("seals");
        for (name, data, opens) in [
            ("64 MiB email", &sealed, true),
            ("64 MiB email, a byte changed", &tampered, false),
            ("64 MiB and a byte", &over, false),
            ("1 GiB of zeros gzipped", &bomb, false),
        ] {
            let mut times = Vec::new();
            for _ in 0..5 {
                let start = std::time::Instant::now();
                assert_eq!(open(&key(), data).is_ok(), opens, "{name}");
                times.push(start.elapsed().as_secs_f64());
            }
            times.sort_by(f64::total_cmp);
            println!(
                "{name}: {} bytes sealed, median {:.2} s, {:.2} to {:.2} s",
                data.len(),
                times[2],
                times[0],
                times[4]
            );
        }
    }

    #[test]
    fn an_archive_is_kept_until_its_week_is_past_retention() {
        let wednesday = NaiveDate::from_ymd_opt(2026, 11, 11)
            .unwrap()
            .and_hms_opt(13, 0, 0)
            .unwrap();
        let (start, end) = week_of(wednesday);
        assert_eq!(start.to_string(), "2026-11-09 00:00:00");
        assert_eq!(end.to_string(), "2026-11-16 00:00:00");
        assert_eq!(
            kept_until(wednesday, 30).to_rfc3339(),
            "2026-12-16T00:00:00+00:00"
        );
    }
}
