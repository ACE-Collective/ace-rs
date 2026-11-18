//! The reads a lookup module makes of ACE's own data (PLAN.md 7.2), which `reads.md` beside this
//! file specifies, and the lease API serves at `POST /api/worker/v1/tasks/<id>/reads/<read>`.
//!
//! `api.rs` checks the caller, the lease and that the task's module declares the read. Each read
//! here then finds its subject in the task's root and answers. Built so far: `snort-signature`,
//! `smtp-counts`, `email-thread-domains`, `email-thread` and `newly-registered` (PLAN.md 7.4), the email
//! archive's three (7.5 batch 9), `observable-tags` (7.6) and `svs-capture-state` (7.10 batch 2).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use ace_results::AnalysisType;
use ace_results::types::email::EmailAnalysis;
use ace_results::{ObservableKind, ObservableRef};
use ace_sdk::email_threads;
use ace_sdk::reads::{
    ArchivedEmailAnswer, ArchivedEmailRequest, ArchivedUrlCountAnswer, ArchivedUrlCountRequest,
    Conversation, ConversationMessage, DecryptedArchiveAnswer, DecryptedArchiveRequest,
    EmailThreadAnswer, EmailThreadDomainsAnswer, EmailThreadDomainsRequest, EmailThreadRequest,
    EstablishedDomain, MAX_OBSERVABLE_TAGS, MAX_SVS_DETECTIONS, MessageParticipant,
    NewlyRegisteredAnswer, NewlyRegisteredRequest, ObservableTagsAnswer, ObservableTagsRequest,
    SmtpCountsAnswer, SmtpCountsRequest, SnortSignatureAnswer, SnortSignatureRequest,
    SvsCaptureRow, SvsCaptureStateAnswer, SvsCaptureStateRequest, SvsDetection, SvsFilePath,
};
use regex::Regex;
use serde_json::Value;
use uuid::Uuid;

use crate::db::{Db, DbError};
use crate::email_archive::{ArchiveError, EmailArchive};
use crate::queue::Task;

/// Why a read wasn't answered, as the lease API answers it.
#[derive(Debug)]
pub enum ReadFailure {
    /// 400: the request doesn't read as the read's.
    BadRequest(String),
    /// 403: the subject isn't in the task's root, or isn't what the read takes.
    Forbidden(String),
    /// 503: the store behind the read is down.
    Unavailable(String),
}

impl From<DbError> for ReadFailure {
    fn from(error: DbError) -> Self {
        ReadFailure::Unavailable(format!("the database: {error}"))
    }
}

impl From<sqlx::Error> for ReadFailure {
    fn from(error: sqlx::Error) -> Self {
        ReadFailure::Unavailable(format!("the database: {error}"))
    }
}

/// What the reads read besides the database.
#[derive(Clone, Default)]
pub struct ReadStores {
    snort: Arc<SnortRules>,
    /// The email archive, with the bucket and the key (PLAN.md 7.5 batch 9). None answers its
    /// reads as a core with no key.
    archive: Option<EmailArchive>,
    /// The dispositions the site classifies `tp` or `fp` (PLAN.md 7.10), which `svs-capture-state`
    /// answers with. None is ace3's.
    classified: Option<Arc<BTreeSet<String>>>,
}

impl ReadStores {
    /// The stores, with the snort and suricata rules file at `snort_rules`, if there is one.
    pub fn new(snort_rules: Option<PathBuf>) -> Self {
        ReadStores {
            snort: Arc::new(SnortRules::new(snort_rules)),
            archive: None,
            classified: None,
        }
    }

    pub fn with_classified(mut self, classified: BTreeSet<String>) -> Self {
        self.classified = Some(Arc::new(classified));
        self
    }

    /// Whether the site classifies `disposition` `tp` or `fp`.
    fn is_classified(&self, disposition: Option<&str>) -> bool {
        let Some(disposition) = disposition else {
            return false;
        };
        match &self.classified {
            Some(classified) => classified.contains(disposition),
            None => ace_sdk::ACE3_DISPOSITION_CLASSES
                .iter()
                .any(|(name, _)| *name == disposition),
        }
    }

    pub fn with_archive(mut self, archive: EmailArchive) -> Self {
        self.archive = Some(archive);
        self
    }

    pub fn archive(&self) -> Option<&EmailArchive> {
        self.archive.as_ref()
    }
}

/// Answers read `read` for `task`, whose lease and module were checked.
pub async fn answer(
    db: &Db,
    stores: &ReadStores,
    catalog: &crate::eligibility::Catalog,
    task: &Task,
    read: &str,
    request: Value,
) -> Result<Value, ReadFailure> {
    let answer = match read {
        "snort-signature" => {
            let request: SnortSignatureRequest = parse(request)?;
            serde_json::to_value(snort_signature(db, stores, task, request).await?)
        }
        "smtp-counts" => {
            let request: SmtpCountsRequest = parse(request)?;
            serde_json::to_value(smtp_counts(db, task, request).await?)
        }
        "email-thread-domains" => {
            let request: EmailThreadDomainsRequest = parse(request)?;
            serde_json::to_value(email_thread_domains(db, task, request).await?)
        }
        "email-thread" => {
            let request: EmailThreadRequest = parse(request)?;
            let mut answer = email_thread(db, task, request).await?;
            answer.recording = recording(db, catalog, task).await?;
            serde_json::to_value(answer)
        }
        "newly-registered" => {
            let request: NewlyRegisteredRequest = parse(request)?;
            serde_json::to_value(newly_registered(db, task, request).await?)
        }
        "archived-email" => {
            let request: ArchivedEmailRequest = parse(request)?;
            serde_json::to_value(archived_email(stores, task, request).await?)
        }
        "decrypted-archive" => {
            let request: DecryptedArchiveRequest = parse(request)?;
            serde_json::to_value(decrypted_archive(db, stores, task, request).await?)
        }
        "archived-url-count" => {
            let request: ArchivedUrlCountRequest = parse(request)?;
            serde_json::to_value(archived_url_count(stores, task, request).await?)
        }
        "observable-tags" => {
            let request: ObservableTagsRequest = parse(request)?;
            serde_json::to_value(observable_tags(db, task, request).await?)
        }
        "svs-capture-state" => {
            let request: SvsCaptureStateRequest = parse(request)?;
            serde_json::to_value(svs_capture_state(db, stores, task, request).await?)
        }
        other => {
            return Err(ReadFailure::Forbidden(format!(
                "read {other} isn't served by this core"
            )));
        }
    };
    answer.map_err(|e| ReadFailure::Unavailable(format!("the answer doesn't serialize: {e}")))
}

fn parse<T: serde::de::DeserializeOwned>(request: Value) -> Result<T, ReadFailure> {
    serde_json::from_value(request).map_err(|e| ReadFailure::BadRequest(e.to_string()))
}

/// The task's own observable, or `subject` once it's found in the task's root.
async fn subject_in_root(
    db: &Db,
    task: &Task,
    subject: Option<ObservableRef>,
) -> Result<ObservableRef, ReadFailure> {
    let Some(subject) = subject else {
        return Ok(ObservableRef::new(
            task.observable.kind,
            task.observable.value.clone(),
        ));
    };
    if in_root(db, task.root, &subject).await? {
        Ok(subject)
    } else {
        Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't in the task's root",
            subject.kind, subject.value
        )))
    }
}

async fn in_root(db: &Db, root: Uuid, subject: &ObservableRef) -> Result<bool, ReadFailure> {
    let found = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM analysis.observables
                        WHERE root_id = $1 AND type = $2 AND value = $3)",
        root,
        subject.kind.as_str(),
        subject.value,
    )
    .fetch_one(db.pool())
    .await?;
    Ok(found.unwrap_or(false))
}

// ---- the email archive (PLAN.md 7.5 batch 9) ----

/// The task's own observable, which must be of `kind`: the archive's reads answer about nothing else.
fn own_subject(
    task: &Task,
    subject: Option<ObservableRef>,
    kind: ObservableKind,
    read: &str,
) -> Result<String, ReadFailure> {
    if task.observable.kind != kind {
        return Err(ReadFailure::Forbidden(format!(
            "{read} answers for a {kind} observable, and task {}'s is a {}",
            task.id, task.observable.kind
        )));
    }
    if let Some(subject) = subject
        && (subject.kind != task.observable.kind || subject.value != task.observable.value)
    {
        return Err(ReadFailure::Forbidden(format!(
            "{read} answers only for the task's own observable, not {}:{}",
            subject.kind, subject.value
        )));
    }
    Ok(task.observable.value.clone())
}

fn archive(stores: &ReadStores) -> Result<&EmailArchive, ReadFailure> {
    stores
        .archive()
        .ok_or_else(|| ReadFailure::Unavailable("this core has no email archive".to_owned()))
}

/// An archive failure as a read answers it: the database or the bucket down is a 503, and what
/// keeps this email from opening (no key, too large, a bad tag, an object gone) is the answer's
/// `error`, as ace3's module logs it and adds nothing.
fn archive_failure(error: ArchiveError) -> Result<String, ReadFailure> {
    match error {
        ArchiveError::Db(e) => Err(e.into()),
        ArchiveError::Bucket(crate::bucket::BucketError::Store(e)) => {
            Err(ReadFailure::Unavailable(format!("the bucket: {e}")))
        }
        ArchiveError::Bucket(crate::bucket::BucketError::Db(e)) => Err(e.into()),
        other => Ok(other.to_string()),
    }
}

/// An archive failure where nothing but the store can fail: always a failure of the read.
fn read_failure(error: ArchiveError) -> ReadFailure {
    match archive_failure(error) {
        Ok(why) => ReadFailure::Unavailable(why),
        Err(failure) => failure,
    }
}

/// `archived-email`: the newest archived email with the task's Message-ID, opened in the core and
/// put in the task's root, as ace3's `iter_archived_email`.
async fn archived_email(
    stores: &ReadStores,
    task: &Task,
    request: ArchivedEmailRequest,
) -> Result<ArchivedEmailAnswer, ReadFailure> {
    let message_id = own_subject(
        task,
        request.subject,
        ObservableKind::MessageId,
        "archived-email",
    )?;
    let archive = archive(stores)?;
    let Some(archived) = archive
        .find_by_message_id(&message_id)
        .await
        .map_err(read_failure)?
    else {
        tracing::info!(task = task.id.0, root = %task.root, read = "archived-email", "not archived");
        return Ok(ArchivedEmailAnswer::default());
    };
    let opened = match archive.open_archived(&archived).await {
        Ok(email) => archive
            .put_in_root(task.root, &email)
            .await
            .map_err(read_failure),
        Err(e) => match archive_failure(e) {
            Ok(why) => {
                tracing::warn!(
                    task = task.id.0,
                    archive_id = archived.archive_id,
                    "unable to open an archived email: {why}"
                );
                return Ok(ArchivedEmailAnswer {
                    email: None,
                    error: Some(why),
                });
            }
            Err(e) => Err(e),
        },
    }?;
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "archived-email",
        archive_id = archived.archive_id,
        sha256 = %opened.sha256,
        "read"
    );
    Ok(ArchivedEmailAnswer {
        email: Some(opened),
        error: None,
    })
}

/// `decrypted-archive`: the task's own file, a `.gz.e` in the root, opened in the core and put in the
/// root, as ace3's `EncryptedArchiveAnalyzer`.
async fn decrypted_archive(
    db: &Db,
    stores: &ReadStores,
    task: &Task,
    request: DecryptedArchiveRequest,
) -> Result<DecryptedArchiveAnswer, ReadFailure> {
    own_subject(
        task,
        request.subject,
        ObservableKind::File,
        "decrypted-archive",
    )?;
    let path = crate::tree::analysis_file(db.pool(), task.root, task.observable.id)
        .await?
        .map(|record| record.path);
    if !path.as_deref().is_some_and(|p| p.ends_with(".gz.e")) {
        return Err(ReadFailure::Forbidden(format!(
            "decrypted-archive opens a file whose name ends .gz.e, and task {}'s is {path:?}",
            task.id
        )));
    }
    let archive = archive(stores)?;
    let sha256: ace_results::Sha256 = task.observable.value.parse().map_err(|_| {
        ReadFailure::Forbidden(format!("{:?} isn't a sha256", task.observable.value))
    })?;
    let opened = match archive.open_alert_file(&sha256).await {
        Ok(email) => archive.put_in_root(task.root, &email).await,
        Err(e) => Err(e),
    };
    match opened {
        Ok(file) => {
            tracing::info!(
                task = task.id.0,
                root = %task.root,
                read = "decrypted-archive",
                sha256 = %file.sha256,
                "read"
            );
            Ok(DecryptedArchiveAnswer {
                email: Some(file),
                error: None,
            })
        }
        Err(e) => {
            let why = archive_failure(e)?;
            tracing::warn!(task = task.id.0, root = %task.root, "unable to decrypt {sha256}: {why}");
            Ok(DecryptedArchiveAnswer {
                email: None,
                error: Some(why),
            })
        }
    }
}

/// `archived-url-count`: how many archived emails are indexed with the task's URL.
async fn archived_url_count(
    stores: &ReadStores,
    task: &Task,
    request: ArchivedUrlCountRequest,
) -> Result<ArchivedUrlCountAnswer, ReadFailure> {
    let url = own_subject(
        task,
        request.subject,
        ObservableKind::Url,
        "archived-url-count",
    )?;
    let count = archive(stores)?
        .url_count(&url)
        .await
        .map_err(read_failure)?;
    tracing::info!(task = task.id.0, root = %task.root, read = "archived-url-count", count, "read");
    Ok(ArchivedUrlCountAnswer { count })
}

// ---- smtp-counts ----

/// `smtp-counts`: brocess's two counts for an email conversation, as ace3's
/// `query_brocess_by_source_email` and `query_brocess_by_email_conversation` sum them.
async fn smtp_counts(
    db: &Db,
    task: &Task,
    request: SmtpCountsRequest,
) -> Result<SmtpCountsAnswer, ReadFailure> {
    let subject = subject_in_root(db, task, request.subject).await?;
    if subject.kind != ObservableKind::EmailConversation {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't an email_conversation observable",
            subject.kind, subject.value
        )));
    }
    let (sender, recipient) = parse_email_conversation(subject.value.trim());
    let row = sqlx::query!(
        r#"SELECT COALESCE(SUM(numconnections), 0)::bigint AS "source_count!",
                  COALESCE(SUM(numconnections) FILTER (WHERE destination = $2), 0)::bigint
                      AS "conversation_count!"
           FROM brocess.smtplog WHERE source = $1"#,
        sender.as_bytes(),
        recipient.as_bytes(),
    )
    .fetch_one(db.pool())
    .await?;
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "smtp-counts",
        subject = %subject.value,
        "read"
    );
    Ok(SmtpCountsAnswer {
        source_count: row.source_count,
        conversation_count: row.conversation_count,
    })
}

/// ace3's `parse_email_conversation`: `<sender>|<recipient>`, or the whole value as the sender and
/// no recipient when it doesn't split in exactly two (`split('|', 2)`).
pub fn parse_email_conversation(value: &str) -> (&str, &str) {
    let parts: Vec<&str> = value.splitn(3, '|').collect();
    match parts.as_slice() {
        [sender, recipient] => (sender, recipient),
        _ => (value, ""),
    }
}

// ---- newly-registered ----

/// `newly-registered`: ace3's `is_newly_registered` for the task's own fqdn or url, over migration
/// 0039's list. It answers for nothing but the task's own observable, so a module can't probe the
/// list with names of its own.
async fn newly_registered(
    db: &Db,
    task: &Task,
    request: NewlyRegisteredRequest,
) -> Result<NewlyRegisteredAnswer, ReadFailure> {
    let own = ObservableRef::new(task.observable.kind, task.observable.value.clone());
    if let Some(subject) = request.subject
        && subject != own
    {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't the task's own observable, the only one this read answers for",
            subject.kind, subject.value
        )));
    }
    if !own.kind.is_subtype_of(ObservableKind::Fqdn) && !own.kind.is_subtype_of(ObservableKind::Url)
    {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't an fqdn or url observable",
            own.kind, own.value
        )));
    }
    let listed = crate::nrd::answer_for(db.pool(), &own.value).await?;
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "newly-registered",
        subject = %own.value,
        listed,
        "read"
    );
    Ok(NewlyRegisteredAnswer { listed })
}

// ---- observable-tags ----

/// `observable-tags`: ace3's `user_defined_tagging` SELECT, the tags mapped to the task's own
/// observable's type and value (migration 0042's `analysis.observable_tags`), in the order they were
/// mapped. It answers for nothing but the task's own observable, at most `MAX_OBSERVABLE_TAGS`.
async fn observable_tags(
    db: &Db,
    task: &Task,
    request: ObservableTagsRequest,
) -> Result<ObservableTagsAnswer, ReadFailure> {
    let own = ObservableRef::new(task.observable.kind, task.observable.value.clone());
    if let Some(subject) = request.subject
        && subject != own
    {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't the task's own observable, the only one this read answers for",
            subject.kind, subject.value
        )));
    }
    let limit = i64::try_from(MAX_OBSERVABLE_TAGS + 1).unwrap_or(i64::MAX);
    let mut tags = sqlx::query_scalar!(
        "SELECT tag FROM analysis.observable_tags
         WHERE type = $1 AND value_hash = analysis.value_hash($2) AND value = $2
         ORDER BY id LIMIT $3",
        own.kind.as_str(),
        own.value,
        limit,
    )
    .fetch_all(db.pool())
    .await?;
    let truncated = tags.len() > MAX_OBSERVABLE_TAGS;
    tags.truncate(MAX_OBSERVABLE_TAGS);
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "observable-tags",
        tags = tags.len(),
        truncated,
        "read"
    );
    Ok(ObservableTagsAnswer { tags, truncated })
}

// ---- email-thread-domains ----

/// The most participant domains an `email-thread-domains` read may name.
pub const MAX_PARTICIPANT_DOMAINS: usize = 100;
/// The most rows of earlier messages' participants an `email-thread-domains` read reads.
pub const MAX_THREAD_DOMAIN_ROWS: i64 = 10_000;

/// `email-thread-domains`: ace3's `get_established_domains` and `get_thread_message_count` for a
/// thread an email in the task's root belongs to.
async fn email_thread_domains(
    db: &Db,
    task: &Task,
    request: EmailThreadDomainsRequest,
) -> Result<EmailThreadDomainsAnswer, ReadFailure> {
    if request.participant_domains.len() > MAX_PARTICIPANT_DOMAINS {
        return Err(ReadFailure::Forbidden(format!(
            "{} participant domains, past the bound of {MAX_PARTICIPANT_DOMAINS}",
            request.participant_domains.len()
        )));
    }
    if !thread_in_root(
        db,
        task.root,
        &request.thread_id,
        &request.normalized_subject,
    )
    .await?
    {
        return Err(ReadFailure::Forbidden(format!(
            "no email in the task's root belongs to thread {} with that subject",
            request.thread_id
        )));
    }
    let limit = MAX_THREAD_DOMAIN_ROWS + 1;
    // in the order the store wrote them, as InnoDB reads them by its index on the thread
    let rows: Vec<(String, String, String, Option<chrono::NaiveDateTime>)> =
        if matches!(request.thread_method.as_str(), "references" | "in_reply_to") {
            sqlx::query!(
                "SELECT domain, address, role, firstseendate FROM brocess.email_thread_domain
                 WHERE thread_id_hash = $1 ORDER BY id LIMIT $2",
                crate::writes::hash(&request.thread_id),
                limit,
            )
            .fetch_all(db.pool())
            .await?
            .into_iter()
            .map(|r| (r.domain, r.address, r.role, r.firstseendate))
            .collect()
        } else if request.normalized_subject.is_empty() {
            Vec::new()
        } else {
            // same-subject threads that share a participant domain with this email
            // ace3 groups the rows by thread, in the order it first reads each thread
            let rows = sqlx::query!(
                "SELECT d.thread_id_hash, d.domain, d.address, d.role, d.firstseendate
                 FROM brocess.email_thread_domain d
                 WHERE d.thread_id_hash IN (
                     SELECT m.thread_id_hash FROM brocess.email_thread_message m
                     WHERE m.normalized_subject_hash = $1)
                   AND d.thread_id_hash IN (
                     SELECT s.thread_id_hash FROM brocess.email_thread_domain s
                     WHERE s.domain = ANY($2))
                 ORDER BY d.id LIMIT $3",
                crate::writes::hash(&request.normalized_subject),
                &request.participant_domains,
                limit,
            )
            .fetch_all(db.pool())
            .await?;
            let mut threads: Vec<Vec<u8>> = Vec::new();
            for row in &rows {
                if !threads.contains(&row.thread_id_hash) {
                    threads.push(row.thread_id_hash.clone());
                }
            }
            threads
                .iter()
                .flat_map(|thread| rows.iter().filter(move |r| &r.thread_id_hash == thread))
                .map(|r| {
                    (
                        r.domain.clone(),
                        r.address.clone(),
                        r.role.clone(),
                        r.firstseendate,
                    )
                })
                .collect()
        };
    let truncated = rows.len() as i64 > MAX_THREAD_DOMAIN_ROWS;
    let rows = &rows[..rows.len().min(MAX_THREAD_DOMAIN_ROWS as usize)];
    let thread_message_count = sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM brocess.email_thread_message WHERE thread_id_hash = $1"#,
        crate::writes::hash(&request.thread_id),
    )
    .fetch_one(db.pool())
    .await?;
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "email-thread-domains",
        thread = %request.thread_id,
        rows = rows.len(),
        truncated,
        "read"
    );
    Ok(EmailThreadDomainsAnswer {
        established: collapse_thread_domains(rows),
        thread_message_count,
        truncated,
    })
}

/// `_collapse_thread_domains`: one entry per domain, address and role, in the order each was first
/// read, with its earliest sighting. An unknown time never wins over a known one.
fn collapse_thread_domains(
    rows: &[(String, String, String, Option<chrono::NaiveDateTime>)],
) -> Vec<EstablishedDomain> {
    let mut order: Vec<(&str, &str, &str)> = Vec::new();
    let mut earliest: HashMap<(&str, &str, &str), Option<chrono::NaiveDateTime>> = HashMap::new();
    for (domain, address, role, seen) in rows {
        let key = (domain.as_str(), address.as_str(), role.as_str());
        match earliest.get_mut(&key) {
            None => {
                order.push(key);
                earliest.insert(key, *seen);
            }
            Some(kept) => {
                if let Some(seen) = seen
                    && kept.is_none_or(|kept| *seen < kept)
                {
                    *kept = Some(*seen);
                }
            }
        }
    }
    order
        .into_iter()
        .map(|key @ (domain, address, role)| EstablishedDomain {
            domain: domain.to_owned(),
            address: address.to_owned(),
            role: role.to_owned(),
            first_seen: earliest[&key].map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()),
        })
        .collect()
}

/// Whether an email in the root belongs to `thread_id`, by its Message-ID, an In-Reply-To or a
/// References id, and has `normalized_subject`.
async fn thread_in_root(
    db: &Db,
    root: Uuid,
    thread_id: &str,
    normalized_subject: &str,
) -> Result<bool, ReadFailure> {
    let details = sqlx::query_scalar!(
        r#"SELECT details FROM analysis.results
           WHERE root_id = $1 AND analysis_type = $2
             AND jsonb_typeof(details -> 'email') = 'object'"#,
        root,
        EmailAnalysis::NAME,
    )
    .fetch_all(db.pool())
    .await?;
    Ok(details.into_iter().any(|details| {
        serde_json::from_value::<EmailAnalysis>(details)
            .ok()
            .and_then(|analysis| analysis.email)
            .is_some_and(|email| {
                email_threads::thread_ids(&email)
                    .iter()
                    .any(|id| id == thread_id)
                    && email_threads::normalized_subject(&email) == normalized_subject
            })
    }))
}

// ---- email-thread ----

/// Whether a module that writes `email-thread` has a task in the task's root that hasn't finished.
async fn recording(
    db: &Db,
    catalog: &crate::eligibility::Catalog,
    task: &Task,
) -> Result<bool, ReadFailure> {
    let recorders: Vec<String> = catalog
        .iter()
        .filter(|c| {
            c.manifest
                .writes
                .contains(&<ace_sdk::writes::EmailThread as ace_sdk::writes::WriteKind>::WRITE)
        })
        .map(|c| c.key.clone())
        .collect();
    if recorders.is_empty() {
        return Ok(false);
    }
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (
               SELECT 1 FROM queue.tasks
               WHERE root_id = $1 AND module = ANY($2)
                 AND state IN ('queued', 'delayed', 'running')
           ) AS "pending!""#,
        task.root,
        &recorders,
    )
    .fetch_one(db.pool())
    .await?)
}

/// The most messages, and the most threads, an `email-thread` read assembles, whatever it asks.
pub const MAX_CONVERSATION: u32 = 500;

/// A message row as `email-thread` reads it.
struct MessageRow {
    thread_id: String,
    message_id: String,
    message_id_hex: String,
    in_reply_to: Option<String>,
    normalized_subject: Option<String>,
    from_address: Option<String>,
    from_domain: Option<String>,
    direction: Option<i16>,
    message_date: Option<chrono::NaiveDateTime>,
    insert_date: chrono::NaiveDateTime,
}

impl From<MessageRow> for ConversationMessage {
    fn from(r: MessageRow) -> Self {
        ConversationMessage {
            thread_id: r.thread_id,
            message_id: r.message_id,
            message_id_hex: r.message_id_hex,
            in_reply_to: r.in_reply_to,
            normalized_subject: r.normalized_subject,
            from_address: r.from_address,
            from_domain: r.from_domain,
            direction: r.direction,
            message_date: when(r.message_date),
            insert_date: when(Some(r.insert_date)),
        }
    }
}

fn when(time: Option<chrono::NaiveDateTime>) -> Option<String> {
    time.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// `email-thread`: ace3's `get_conversation` for a `message_id` observable in the task's root.
async fn email_thread(
    db: &Db,
    task: &Task,
    request: EmailThreadRequest,
) -> Result<EmailThreadAnswer, ReadFailure> {
    let subject = subject_in_root(db, task, request.subject).await?;
    if subject.kind != ObservableKind::MessageId {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't a message_id observable",
            subject.kind, subject.value
        )));
    }
    let max_messages = request.max_messages.clamp(1, MAX_CONVERSATION) as usize;
    let max_threads = request.max_threads.clamp(1, MAX_CONVERSATION) as usize;
    let message_id = email_threads::normalize_message_id(&subject.value);
    let pool = db.pool();
    let anchor = sqlx::query!(
        r#"SELECT thread_id_hash, normalized_subject, thread_id, message_id
           FROM brocess.email_thread_message WHERE message_id_hash = $1 ORDER BY id LIMIT 1"#,
        crate::writes::hash(&message_id),
    )
    .fetch_optional(pool)
    .await?;
    let Some(anchor) = anchor else {
        return Ok(EmailThreadAnswer {
            conversation: None,
            recording: false,
        });
    };
    let header_threaded = anchor.thread_id != anchor.message_id;
    let mut roles: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut addresses: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut roles_truncated = false;
    let mut link_domains = Vec::new();
    let mut threads_capped = false;
    let mut threads = vec![anchor.thread_id_hash.clone()];
    if let (false, Some(normalized)) = (header_threaded, anchor.normalized_subject.as_deref())
        && !normalized.is_empty()
    {
        let subject_hash = crate::writes::hash(normalized);
        let rows = sqlx::query!(
            "SELECT d.thread_id_hash, d.domain, d.address, d.role
             FROM brocess.email_thread_domain d
             WHERE d.thread_id_hash IN (
                 SELECT m.thread_id_hash FROM brocess.email_thread_message m
                 WHERE m.normalized_subject_hash = $1)
             ORDER BY d.id LIMIT $2",
            subject_hash,
            MAX_THREAD_DOMAIN_ROWS + 1,
        )
        .fetch_all(pool)
        .await?;
        roles_truncated = rows.len() as i64 > MAX_THREAD_DOMAIN_ROWS;
        let rows = &rows[..rows.len().min(MAX_THREAD_DOMAIN_ROWS as usize)];
        let anchor_domains: BTreeSet<&str> = rows
            .iter()
            .filter(|r| r.thread_id_hash == anchor.thread_id_hash)
            .map(|r| r.domain.as_str())
            .collect();
        if !anchor_domains.is_empty() {
            // each thread in the order first read, kept when it shares a domain with the anchor's
            let mut order: Vec<&Vec<u8>> = Vec::new();
            for row in rows {
                if !order.contains(&&row.thread_id_hash) {
                    order.push(&row.thread_id_hash);
                }
            }
            let overlapping: Vec<&Vec<u8>> = order
                .into_iter()
                .filter(|thread| {
                    rows.iter().any(|r| {
                        &&r.thread_id_hash == thread && anchor_domains.contains(r.domain.as_str())
                    })
                })
                .collect();
            let mut linked = BTreeSet::new();
            for row in rows
                .iter()
                .filter(|r| overlapping.contains(&&r.thread_id_hash))
            {
                roles
                    .entry(row.domain.clone())
                    .or_default()
                    .insert(row.role.clone());
                addresses
                    .entry(row.domain.clone())
                    .or_default()
                    .insert(row.address.clone());
                if row.thread_id_hash != anchor.thread_id_hash
                    && anchor_domains.contains(row.domain.as_str())
                {
                    linked.insert(row.domain.clone());
                }
            }
            link_domains = linked.into_iter().collect();
            // oldest first, by each thread's earliest message, as the message cap keeps the oldest
            let dates = sqlx::query!(
                "SELECT thread_id_hash, MIN(message_date) AS message_date,
                        MIN(insert_date) AS insert_date
                 FROM brocess.email_thread_message WHERE normalized_subject_hash = $1
                 GROUP BY thread_id_hash",
                subject_hash,
            )
            .fetch_all(pool)
            .await?;
            let date_of = |thread: &Vec<u8>| {
                dates
                    .iter()
                    .find(|d| &d.thread_id_hash == thread)
                    .map_or((None, None), |d| (d.message_date, d.insert_date))
            };
            let mut siblings: Vec<Vec<u8>> = overlapping.into_iter().cloned().collect();
            siblings.sort_by_key(|thread| {
                let (message_date, insert_date) = date_of(thread);
                (
                    message_date.is_none(),
                    message_date,
                    insert_date,
                    hex(thread),
                )
            });
            if !siblings.contains(&anchor.thread_id_hash) {
                siblings.insert(0, anchor.thread_id_hash.clone());
            }
            if siblings.len() > max_threads {
                threads_capped = true;
                threads = std::iter::once(anchor.thread_id_hash.clone())
                    .chain(
                        siblings
                            .into_iter()
                            .filter(|t| *t != anchor.thread_id_hash)
                            .take(max_threads - 1),
                    )
                    .collect();
            } else {
                threads = siblings;
            }
        }
    }
    let mut messages: Vec<ConversationMessage> = sqlx::query_as!(
        MessageRow,
        r#"SELECT thread_id, message_id, upper(encode(message_id_hash, 'hex')) AS "message_id_hex!",
                  in_reply_to, normalized_subject, from_address, from_domain, direction,
                  message_date, insert_date
           FROM brocess.email_thread_message WHERE thread_id_hash = ANY($1)
           ORDER BY message_date IS NULL, message_date, insert_date, id LIMIT $2"#,
        &threads,
        (max_messages + 1) as i64,
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(ConversationMessage::from)
    .collect();
    let messages_capped = messages.len() > max_messages;
    if messages_capped {
        messages.truncate(max_messages);
        // the message the analyst is looking at stays, whatever the cap
        if !messages.iter().any(|m| m.message_id == message_id) {
            let anchor = sqlx::query_as!(
                MessageRow,
                r#"SELECT thread_id, message_id,
                          upper(encode(message_id_hash, 'hex')) AS "message_id_hex!", in_reply_to,
                          normalized_subject, from_address, from_domain, direction, message_date,
                          insert_date
                   FROM brocess.email_thread_message WHERE message_id_hash = $1
                   ORDER BY id LIMIT 1"#,
                crate::writes::hash(&message_id),
            )
            .fetch_optional(pool)
            .await?;
            messages.extend(anchor.map(ConversationMessage::from));
        }
    }
    // by thread, then as written, as InnoDB reads a list of threads through its index
    let participant_rows = sqlx::query!(
        r#"SELECT upper(encode(message_id_hash, 'hex')) AS message_id_hex, domain, address, role,
                  firstseendate
           FROM brocess.email_thread_domain WHERE thread_id_hash = ANY($1)
           ORDER BY thread_id_hash, id LIMIT $2"#,
        &threads,
        MAX_THREAD_DOMAIN_ROWS + 1,
    )
    .fetch_all(pool)
    .await?;
    roles_truncated |= participant_rows.len() as i64 > MAX_THREAD_DOMAIN_ROWS;
    let participants: Vec<MessageParticipant> = participant_rows
        .into_iter()
        .take(MAX_THREAD_DOMAIN_ROWS as usize)
        .map(|r| {
            roles
                .entry(r.domain.clone())
                .or_default()
                .insert(r.role.clone());
            addresses
                .entry(r.domain.clone())
                .or_default()
                .insert(r.address.clone());
            MessageParticipant {
                message_id_hex: r.message_id_hex,
                domain: r.domain,
                address: r.address,
                role: r.role,
                first_seen: when(r.firstseendate),
            }
        })
        .collect();
    let mut per_thread: Vec<(&str, u32)> = Vec::new();
    for m in &messages {
        match per_thread.iter_mut().find(|(t, _)| *t == m.thread_id) {
            Some((_, count)) => *count += 1,
            None => per_thread.push((&m.thread_id, 1)),
        }
    }
    let mut thread_message_counts: Vec<u32> = per_thread.into_iter().map(|(_, n)| n).collect();
    thread_message_counts.sort_unstable_by(|a, b| b.cmp(a));
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "email-thread",
        subject = %message_id,
        messages = messages.len(),
        threads = threads.len(),
        "read"
    );
    let sets = |map: BTreeMap<String, BTreeSet<String>>| {
        map.into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect()
    };
    Ok(EmailThreadAnswer {
        conversation: Some(Conversation {
            anchor_message_id: message_id,
            normalized_subject: anchor.normalized_subject,
            thread_count: threads.len() as u32,
            thread_method: if header_threaded { "headers" } else { "self" }.to_owned(),
            link_domains,
            thread_message_counts,
            domain_roles: sets(roles),
            domain_addresses: sets(addresses),
            messages,
            participants,
            truncated: messages_capped || threads_capped,
            roles_truncated,
        }),
        recording: false,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

// ---- snort-signature ----

/// `snort-signature`: the rule line with the subject's sid and rev.
async fn snort_signature(
    db: &Db,
    stores: &ReadStores,
    task: &Task,
    request: SnortSignatureRequest,
) -> Result<SnortSignatureAnswer, ReadFailure> {
    let subject = subject_in_root(db, task, request.subject).await?;
    if subject.kind != ObservableKind::SnortSig {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't a snort_sig observable",
            subject.kind, subject.value
        )));
    }
    // SnortSignatureObservable: `<gid>:<sid>:<rev>`
    let parts: Vec<&str> = subject.value.trim().split(':').collect();
    let [_, sid, rev] = parts.as_slice() else {
        return Ok(SnortSignatureAnswer { rule: None });
    };
    let rule = stores.snort.rule(sid, rev)?;
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "snort-signature",
        subject = %subject.value,
        found = rule.is_some(),
        "read"
    );
    Ok(SnortSignatureAnswer { rule })
}

/// The snort and suricata rules file `ace signatures build-db` indexes into Redis in ace3
/// (`saq/modules/snort.py`), indexed here in memory by `<sid>:<rev>`, again whenever the file
/// changes.
#[derive(Default)]
pub struct SnortRules {
    path: Option<PathBuf>,
    index: Mutex<Option<SnortIndex>>,
}

struct SnortIndex {
    modified: Option<SystemTime>,
    size: u64,
    rules: HashMap<String, String>,
}

impl SnortRules {
    pub fn new(path: Option<PathBuf>) -> Self {
        SnortRules {
            path,
            index: Mutex::new(None),
        }
    }

    /// The rule with `sid` and `rev`, or None. No file is no rules, as ace3 has none until the
    /// index is built. A file that can't be read is the store being down.
    pub fn rule(&self, sid: &str, rev: &str) -> Result<Option<String>, ReadFailure> {
        let Some(path) = &self.path else {
            return Ok(None);
        };
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ReadFailure::Unavailable(format!(
                    "the snort rules {}: {e}",
                    path.display()
                )));
            }
        };
        let mut index = self
            .index
            .lock()
            .map_err(|_| ReadFailure::Unavailable("the snort rules' index is poisoned".into()))?;
        let modified = metadata.modified().ok();
        let fresh = index
            .as_ref()
            .is_some_and(|i| i.modified == modified && i.size == metadata.len());
        if !fresh {
            *index = Some(SnortIndex {
                modified,
                size: metadata.len(),
                rules: index_rules(path)?,
            });
        }
        Ok(index
            .as_ref()
            .and_then(|i| i.rules.get(&format!("{sid}:{rev}")).cloned()))
    }
}

/// `_build_signature_db`: each line, stripped, under the `<sid>:<rev>` it names, a later line
/// taking the place of an earlier one with the same. ace3's pattern,
/// `^(?=.*sid:([0-9]+);)(?=.*rev:([0-9]+);).*$`, takes the last `sid:N;` and the last `rev:N;` of
/// a line, since its lookaheads are greedy.
fn index_rules(path: &Path) -> Result<HashMap<String, String>, ReadFailure> {
    let bytes = std::fs::read(path).map_err(|e| {
        ReadFailure::Unavailable(format!("the snort rules {}: {e}", path.display()))
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let sid = Regex::new(r"sid:([0-9]+);").expect("a valid pattern");
    let rev = Regex::new(r"rev:([0-9]+);").expect("a valid pattern");
    let last = |pattern: &Regex, line: &str| -> Option<String> {
        pattern.captures_iter(line).last().map(|c| c[1].to_owned())
    };
    let mut rules = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let (Some(sid), Some(rev)) = (last(&sid, line), last(&rev, line)) {
            rules.insert(format!("{sid}:{rev}"), line.to_owned());
        }
    }
    tracing::info!(
        "indexed {} snort signatures from {}",
        rules.len(),
        path.display()
    );
    Ok(rules)
}

// ---- svs-capture-state (PLAN.md 7.10 batch 2) ----

/// `svs-capture-state`: what `svs_yara_sample_capture` reads of ace3's database before it captures, for
/// the task's own file only: the alert's disposition and whether the site classifies it (ace3's
/// `get_disposition_class`), whether a test run that isn't reviewed holds the alert (`svs.unreviewed_run`,
/// ace3's `unreviewed_run_condition`), the file's paths and their `yara_meta` tags, the detections on it,
/// at most `MAX_SVS_DETECTIONS`, whether SVS deleted it, and what SVS captured of it from this root.
async fn svs_capture_state(
    db: &Db,
    stores: &ReadStores,
    task: &Task,
    request: SvsCaptureStateRequest,
) -> Result<SvsCaptureStateAnswer, ReadFailure> {
    if task.observable.kind != ObservableKind::File {
        return Err(ReadFailure::Forbidden(format!(
            "svs-capture-state answers for a file, and task {}'s observable is a {}",
            task.id, task.observable.kind
        )));
    }
    let own = ObservableRef::new(task.observable.kind, task.observable.value.clone());
    if let Some(subject) = request.subject
        && subject != own
    {
        return Err(ReadFailure::Forbidden(format!(
            "{}:{} isn't the task's own file, the only one this read answers for",
            subject.kind, subject.value
        )));
    }
    let root = sqlx::query!(
        r#"SELECT alerted_at IS NOT NULL AS "alert!", disposition,
                  svs.unreviewed_run(id) AS "unreviewed!"
           FROM analysis.roots WHERE id = $1"#,
        task.root,
    )
    .fetch_one(db.pool())
    .await?;
    let paths = sqlx::query!(
        "SELECT path, yara_meta FROM analysis.files
         WHERE root_id = $1 AND observable_id = $2 ORDER BY created_at, path",
        task.root,
        task.observable.id.0,
    )
    .fetch_all(db.pool())
    .await?
    .into_iter()
    .map(|row| SvsFilePath {
        path: row.path,
        yara_meta: row.yara_meta,
    })
    .collect();
    let limit = i64::try_from(MAX_SVS_DETECTIONS + 1).unwrap_or(i64::MAX);
    let mut detections: Vec<SvsDetection> = sqlx::query!(
        "SELECT description, details, signature_uuid, signature_version FROM analysis.detections
         WHERE root_id = $1 AND observable_id = $2 ORDER BY id LIMIT $3",
        task.root,
        task.observable.id.0,
        limit,
    )
    .fetch_all(db.pool())
    .await?
    .into_iter()
    .map(|row| SvsDetection {
        description: row.description,
        details: row.details,
        signature_uuid: row.signature_uuid,
        signature_version: row.signature_version,
    })
    .collect();
    let detections_truncated = detections.len() > MAX_SVS_DETECTIONS;
    detections.truncate(MAX_SVS_DETECTIONS);
    let deleted = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT FROM svs.sample_deletions WHERE sha256 = $1) AS "deleted!""#,
        task.observable.value,
    )
    .fetch_one(db.pool())
    .await?;
    let captures = sqlx::query!(
        "SELECT rule_uuid, state, missing_reason FROM svs.yara_captures
         WHERE root_id = $1 AND sha256 = $2 ORDER BY rule_uuid",
        task.root,
        task.observable.value,
    )
    .fetch_all(db.pool())
    .await?
    .into_iter()
    .map(|row| SvsCaptureRow {
        rule_uuid: row.rule_uuid,
        state: row.state,
        missing_reason: row.missing_reason,
    })
    .collect();
    let classified = stores.is_classified(root.disposition.as_deref());
    tracing::info!(
        task = task.id.0,
        root = %task.root,
        read = "svs-capture-state",
        classified,
        unreviewed = root.unreviewed,
        deleted,
        detections_truncated,
        "read"
    );
    Ok(SvsCaptureStateAnswer {
        alert: root.alert,
        disposition: root.disposition,
        classified,
        unreviewed_run: root.unreviewed,
        paths,
        detections,
        detections_truncated,
        deleted,
        captures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_conversation_splits_in_two_or_is_all_sender() {
        assert_eq!(parse_email_conversation("a@x|b@y"), ("a@x", "b@y"));
        assert_eq!(parse_email_conversation("a@x"), ("a@x", ""));
        assert_eq!(parse_email_conversation("a@x|b@y|c@z"), ("a@x|b@y|c@z", ""));
        assert_eq!(parse_email_conversation("|b@y"), ("", "b@y"));
    }

    #[test]
    fn rules_are_indexed_by_their_last_sid_and_rev_and_again_when_the_file_changes() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("snort.rules");
        std::fs::write(
            &path,
            "# a comment, sid:1; rev:1;\n\
             alert tcp any any -> any any (msg:\"one\"; rev:2; sid:100;)  \n\
             alert tcp any any -> any any (msg:\"no sid\"; rev:1;)\n\
             alert udp any any -> any any (msg:\"two\"; sid:7; sid:200; rev:3;)\n",
        )
        .expect("writes");
        let rules = SnortRules::new(Some(path.clone()));
        assert_eq!(
            rules.rule("100", "2").ok().flatten().as_deref(),
            Some("alert tcp any any -> any any (msg:\"one\"; rev:2; sid:100;)")
        );
        assert!(rules.rule("200", "3").ok().flatten().is_some());
        assert_eq!(rules.rule("7", "3").ok().flatten(), None);
        assert_eq!(
            rules.rule("1", "1").ok().flatten().as_deref(),
            Some("# a comment, sid:1; rev:1;")
        );
        std::fs::write(
            &path,
            "alert ip any any -> any any (sid:100; rev:2; msg:\"new\";)\n",
        )
        .expect("writes");
        assert_eq!(
            rules.rule("100", "2").ok().flatten().as_deref(),
            Some("alert ip any any -> any any (sid:100; rev:2; msg:\"new\";)")
        );
        assert_eq!(rules.rule("200", "3").ok().flatten(), None);
        std::fs::remove_file(&path).expect("removes");
        assert_eq!(rules.rule("100", "2").ok().flatten(), None);
        assert_eq!(SnortRules::new(None).rule("100", "2").ok().flatten(), None);
    }
}
