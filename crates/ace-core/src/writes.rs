//! The writes a lookup module makes to ACE's own data (PLAN.md 7.2), which land with its task's end
//! in the end's own transaction. `reads.md` beside this file is the contract.
//!
//! `api.rs` takes them from a `TaskEnd` that's a result or a skip. `check` refuses a write the task's
//! module doesn't declare, a body that doesn't read, one past its bound, or one about an email that
//! isn't the task's own; `apply` then writes them in the transaction that ends the task. ace3 audits
//! none of these writes, so they are logged, with the task and the root, and write no audit row.
//! Built: `smtp-log` and `email-thread` (PLAN.md 7.4, `email_logger`), and `email-archive` (7.5 batch
//! 9, `email_archiver`), which `email_archive` seals in `check` and lands in `apply`; and `svs-capture`
//! (7.10 batch 2, `svs_yara_sample_capture`), whose bytes `svs::samples::prepare` reads in `check` and
//! `svs::samples::land` puts in the `svs_samples` pool in `apply`; and `remediation-check` (PLAN.md
//! decision 32, for a site's module), which queues a remediation check through `actions` and records
//! the module's own answer as a try. It alone lands with a delay too
//! (`ace_sdk::writes::lands_on_delay`).

use ace_results::AnalysisType;
use ace_results::types::email::{EmailAnalysis, EmailDetails};
use ace_sdk::Manifest;
use ace_sdk::actions::{ActionKind, ProbeOutcome};
use ace_sdk::email_threads;
use ace_sdk::writes::{
    ArchivedEmailRecord, CheckRequest, MAX_CHECK_CONTEXT_BYTES, MAX_SVS_CAPTURES, SmtpLogRows,
    SvsCaptures, ThreadRecord, WireWrite,
};
use chrono::NaiveDateTime;
use sha2::{Digest, Sha256};

use crate::actions::ActionCatalog;
use crate::bucket::Bucket;
use crate::db::{Db, DbError, Tx};
use crate::email_archive::{EmailArchive, PrepareFailure};
use crate::queue::Task;

/// The most rows one `smtp-log` write adds: ace3 writes one per recipient, with no bound.
pub const MAX_SMTP_ROWS: usize = 1000;
/// The most participants one `email-thread` write records.
pub const MAX_PARTICIPANTS: usize = 1000;
/// ace3's smtplog columns are varbinary(255).
const SMTP_ADDRESS_BYTES: usize = 255;

/// Why a task's writes were refused.
#[derive(Debug)]
pub enum WriteFailure {
    /// 400: a body doesn't read as its write's.
    BadRequest(String),
    /// 403: the module doesn't declare the write, or it's past its bound or about another email.
    Forbidden(String),
    Db(DbError),
}

impl From<DbError> for WriteFailure {
    fn from(error: DbError) -> Self {
        WriteFailure::Db(error)
    }
}

impl From<sqlx::Error> for WriteFailure {
    fn from(error: sqlx::Error) -> Self {
        WriteFailure::Db(error.into())
    }
}

/// A write that passed its checks.
#[derive(Debug, Clone)]
pub enum Checked {
    SmtpLog(SmtpLogRows),
    EmailThread(ThreadRecord),
    /// The email, sealed, and what it's found by (PLAN.md 7.5 batch 9).
    EmailArchive(Box<crate::email_archive::Prepared>),
    /// The file's captures for SVS, each with its bytes found (PLAN.md 7.10 batch 2).
    SvsCapture(Vec<crate::svs::samples::Prepared>),
    /// A remediation check of the task's own observable by `probe`, a handler of the catalog's
    /// (PLAN.md decision 32).
    RemediationCheck {
        probe: &'static str,
        context: Option<serde_json::Value>,
        outcome: Option<ProbeOutcome>,
    },
}

/// What the core checks a task's writes against besides the task: its email archive, its bucket,
/// the action handlers its catalog has, and whether the writes came with a delay.
#[derive(Clone, Copy)]
pub struct Stores<'a> {
    pub archive: Option<&'a EmailArchive>,
    pub bucket: &'a Bucket,
    pub actions: &'a ActionCatalog,
}

/// Checks `writes` for `task`, whose module is `manifest`, before its end's transaction. An
/// `email-archive` is sealed here, with the archive's key, and an `svs-capture`'s bytes are read
/// from the bucket. With a delay (`on_delay`), only a write that lands with one may come.
pub async fn check(
    db: &Db,
    stores: Stores<'_>,
    manifest: Option<&Manifest>,
    task: &Task,
    writes: Vec<WireWrite>,
    on_delay: bool,
) -> Result<Vec<Checked>, WriteFailure> {
    let Stores {
        archive, bucket, ..
    } = stores;
    let mut checked = Vec::new();
    for write in writes {
        let declared = manifest.is_some_and(|m| m.writes.iter().any(|w| w.name == write.write));
        if !declared {
            return Err(WriteFailure::Forbidden(format!(
                "{} doesn't declare the write {}",
                task.module, write.write
            )));
        }
        if on_delay && !ace_sdk::writes::lands_on_delay(&write.write) {
            return Err(WriteFailure::Forbidden(format!(
                "the write {} lands only with a result or a skip, not a delay",
                write.write
            )));
        }
        match write.write.as_str() {
            "smtp-log" => {
                let rows: SmtpLogRows = parse(write.body)?;
                if rows.rows.len() > MAX_SMTP_ROWS {
                    return Err(WriteFailure::Forbidden(format!(
                        "smtp-log adds {} rows, past its bound of {MAX_SMTP_ROWS}",
                        rows.rows.len()
                    )));
                }
                own_email(db, task).await?;
                checked.push(Checked::SmtpLog(rows));
            }
            "email-thread" => {
                let record: ThreadRecord = parse(write.body)?;
                if record.participants.len() > MAX_PARTICIPANTS {
                    return Err(WriteFailure::Forbidden(format!(
                        "email-thread records {} participants, past its bound of {MAX_PARTICIPANTS}",
                        record.participants.len()
                    )));
                }
                let email = own_email(db, task).await?;
                let ids = email_threads::thread_ids(&email);
                let subject = email_threads::normalized_subject(&email);
                let subject_matches = match &record.normalized_subject {
                    Some(normalized) => *normalized == subject,
                    None => subject.is_empty(),
                };
                if !ids.contains(&record.thread_id)
                    || !ids.contains(&record.message_id)
                    || !subject_matches
                {
                    return Err(WriteFailure::Forbidden(format!(
                        "email-thread names a thread, message or subject that isn't the task's email's: {} {}",
                        record.thread_id, record.message_id
                    )));
                }
                checked.push(Checked::EmailThread(record));
            }
            "email-archive" => {
                if checked
                    .iter()
                    .any(|c| matches!(c, Checked::EmailArchive(_)))
                {
                    return Err(WriteFailure::Forbidden(
                        "a task archives its email once".to_owned(),
                    ));
                }
                let record: ArchivedEmailRecord = parse(write.body)?;
                let email = own_email(db, task).await?;
                let Some(archive) = archive else {
                    return Err(WriteFailure::Forbidden(
                        "this core has no email archive".to_owned(),
                    ));
                };
                match archive
                    .prepare(task, email.message_id.as_deref(), record)
                    .await
                {
                    Ok(prepared) => checked.push(Checked::EmailArchive(Box::new(prepared))),
                    Err(PrepareFailure::Refused(why)) => return Err(WriteFailure::Forbidden(why)),
                    Err(PrepareFailure::Failed(e)) => {
                        return Err(WriteFailure::Db(DbError::Decode(format!(
                            "archiving the email: {e}"
                        ))));
                    }
                }
            }
            "svs-capture" => {
                if checked.iter().any(|c| matches!(c, Checked::SvsCapture(_))) {
                    return Err(WriteFailure::Forbidden(
                        "a task captures its file once".to_owned(),
                    ));
                }
                let captures: SvsCaptures = parse(write.body)?;
                let candidates = svs_candidates(db, task, captures).await?;
                let prepared = crate::svs::samples::prepare(
                    db,
                    bucket,
                    task.root,
                    Some(task.observable.id.0),
                    candidates,
                )
                .await?;
                checked.push(Checked::SvsCapture(prepared));
            }
            "remediation-check" => {
                let request: CheckRequest = parse(write.body)?;
                let check = remediation_check(stores.actions, task, request)?;
                let probe = match &check {
                    Checked::RemediationCheck { probe, .. } => *probe,
                    _ => unreachable!("remediation_check makes one"),
                };
                if checked
                    .iter()
                    .any(|c| matches!(c, Checked::RemediationCheck { probe: p, .. } if *p == probe))
                {
                    return Err(WriteFailure::Forbidden(format!(
                        "a task asks for one remediation check by {probe}"
                    )));
                }
                checked.push(check);
            }
            other => {
                return Err(WriteFailure::Forbidden(format!(
                    "write {other} isn't served by this core"
                )));
            }
        }
    }
    Ok(checked)
}

/// The candidates of an `svs-capture` write, once each is the task's own file, for a rule uuid ace3
/// captures, that a detection on the file names, under one of the file's paths in the root. One rule
/// twice is refused, as ace3 makes one candidate per (file, rule).
async fn svs_candidates(
    db: &Db,
    task: &Task,
    captures: SvsCaptures,
) -> Result<Vec<ace_sdk::writes::SvsCaptureCandidate>, WriteFailure> {
    use crate::svs::samples::MAX_RULE_UUID;
    if captures.captures.len() > MAX_SVS_CAPTURES {
        return Err(WriteFailure::Forbidden(format!(
            "svs-capture makes {} captures, past its bound of {MAX_SVS_CAPTURES}",
            captures.captures.len()
        )));
    }
    if task.observable.kind != ace_results::ObservableKind::File {
        return Err(WriteFailure::Forbidden(format!(
            "svs-capture captures a file, and task {}'s observable is a {}",
            task.id, task.observable.kind
        )));
    }
    let signatures: Vec<String> = sqlx::query_scalar!(
        r#"SELECT DISTINCT signature_uuid AS "signature_uuid!" FROM analysis.detections
           WHERE root_id = $1 AND observable_id = $2 AND signature_uuid IS NOT NULL"#,
        task.root,
        task.observable.id.0,
    )
    .fetch_all(db.pool())
    .await?;
    let paths: Vec<String> = sqlx::query_scalar!(
        "SELECT path FROM analysis.files WHERE root_id = $1 AND observable_id = $2",
        task.root,
        task.observable.id.0,
    )
    .fetch_all(db.pool())
    .await?;
    let mut seen = std::collections::BTreeSet::new();
    for candidate in &captures.captures {
        let refused = if candidate.sha256 != task.observable.value {
            Some(format!(
                "svs-capture names the file {}, which isn't the task's own",
                candidate.sha256
            ))
        } else if candidate.rule_uuid.is_empty()
            || candidate.rule_uuid.chars().count() > MAX_RULE_UUID
        {
            Some(format!(
                "svs-capture names the rule uuid {:?}, which SVS doesn't capture",
                candidate.rule_uuid
            ))
        } else if !signatures.contains(&candidate.rule_uuid) {
            Some(format!(
                "svs-capture names the rule {}, which no detection on the file is of",
                candidate.rule_uuid
            ))
        } else if !paths.contains(&candidate.file_path) {
            Some(format!(
                "svs-capture names the path {:?}, which isn't the file's in the root",
                candidate.file_path
            ))
        } else if !seen.insert(candidate.rule_uuid.clone()) {
            Some(format!(
                "svs-capture names the rule {} twice",
                candidate.rule_uuid
            ))
        } else {
            None
        };
        if let Some(why) = refused {
            return Err(WriteFailure::Forbidden(why));
        }
    }
    Ok(captures.captures)
}

/// A `remediation-check` write, once its probe is a remediation check handler of the core's catalog
/// (so not one the overlay leaves off, PLAN.md decision 28) that acts on the task's observable's
/// type, its context is within its bound, and its answer records no more events than a pool's try
/// may. The check is always of the task's own observable, for the task's root.
fn remediation_check(
    actions: &ActionCatalog,
    task: &Task,
    request: CheckRequest,
) -> Result<Checked, WriteFailure> {
    let Some(spec) = actions.get(ActionKind::RemediationCheck, &request.probe) else {
        return Err(WriteFailure::Forbidden(format!(
            "remediation-check names the probe {:?}, which this core hasn't",
            request.probe
        )));
    };
    if spec.observable_type != task.observable.kind.as_str() {
        return Err(WriteFailure::Forbidden(format!(
            "remediation-check: {} checks a {}, and task {}'s observable is a {}",
            spec.name,
            spec.observable_type,
            task.id,
            task.observable.kind.as_str()
        )));
    }
    let context = request.context.map(serde_json::Value::Object);
    let size = context
        .as_ref()
        .map_or(0, |context| context.to_string().len());
    if size > MAX_CHECK_CONTEXT_BYTES {
        return Err(WriteFailure::Forbidden(format!(
            "remediation-check's context is {size} bytes, past its bound of \
             {MAX_CHECK_CONTEXT_BYTES}"
        )));
    }
    if let Some(ProbeOutcome::FoundEvents { events, .. }) = &request.outcome
        && events.len() > ace_sdk::actions::MAX_EVENTS
    {
        return Err(WriteFailure::Forbidden(format!(
            "remediation-check records {} events, past its bound of {}",
            events.len(),
            ace_sdk::actions::MAX_EVENTS
        )));
    }
    Ok(Checked::RemediationCheck {
        probe: spec.name,
        context,
        outcome: request.outcome,
    })
}

fn parse<T: serde::de::DeserializeOwned>(body: serde_json::Value) -> Result<T, WriteFailure> {
    serde_json::from_value(body).map_err(|e| WriteFailure::BadRequest(e.to_string()))
}

/// The email the task's own observable is: its newest email result in the root that parsed one.
async fn own_email(db: &Db, task: &Task) -> Result<EmailDetails, WriteFailure> {
    let details = sqlx::query_scalar!(
        r#"SELECT details FROM analysis.results
           WHERE root_id = $1 AND observable_id = $2 AND analysis_type = $3
             AND jsonb_typeof(details -> 'email') = 'object'
           ORDER BY id DESC LIMIT 1"#,
        task.root,
        task.observable.id.0,
        EmailAnalysis::NAME,
    )
    .fetch_optional(db.pool())
    .await?;
    let Some(details) = details else {
        return Err(WriteFailure::Forbidden(format!(
            "task {}'s observable has no email result in its root",
            task.id
        )));
    };
    let analysis: EmailAnalysis = serde_json::from_value(details).map_err(|e| {
        WriteFailure::Db(DbError::Decode(format!(
            "an email result doesn't read: {e}"
        )))
    })?;
    analysis
        .email
        .ok_or_else(|| WriteFailure::Forbidden(format!("task {}'s email has no details", task.id)))
}

/// ace3's `UNHEX(SHA2(value, 256))`.
pub fn hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

/// An address as ace3 writes it to smtplog: UTF-8, cut to 255 bytes.
fn smtp_address(address: &str) -> &[u8] {
    let bytes = address.as_bytes();
    &bytes[..bytes.len().min(SMTP_ADDRESS_BYTES)]
}

/// Writes the checked writes in the transaction that ends `task`, or delays it.
pub async fn apply(
    tx: &mut Tx<'_>,
    stores: Stores<'_>,
    task: &Task,
    writes: &[Checked],
) -> Result<(), DbError> {
    let Stores {
        archive, bucket, ..
    } = stores;
    for write in writes {
        match write {
            Checked::SmtpLog(rows) => {
                // one statement per row, as ace3's, so a recipient twice counts twice
                for row in &rows.rows {
                    sqlx::query!(
                        "INSERT INTO brocess.smtplog AS s
                             (source, destination, numconnections, firstconnectdate)
                         VALUES ($1, $2, 1, floor(extract(epoch FROM now())))
                         ON CONFLICT (source, destination)
                         DO UPDATE SET numconnections = s.numconnections + 1",
                        smtp_address(&row.source),
                        smtp_address(&row.destination),
                    )
                    .execute(tx.conn())
                    .await?;
                }
                tracing::info!(
                    task = task.id.0,
                    root = %task.root,
                    write = "smtp-log",
                    rows = rows.rows.len(),
                    "write"
                );
            }
            Checked::EmailThread(record) => record_thread(tx, record).await?,
            Checked::EmailArchive(prepared) => {
                let archive = archive.ok_or_else(|| {
                    DbError::Decode("an email-archive write with no archive".to_owned())
                })?;
                archive.land(tx, prepared).await.map_err(|e| match e {
                    crate::email_archive::ArchiveError::Db(e) => e,
                    crate::email_archive::ArchiveError::Bucket(crate::bucket::BucketError::Db(
                        e,
                    )) => e,
                    other => {
                        DbError::Decode(format!("archiving task {}'s email: {other}", task.id))
                    }
                })?;
            }
            Checked::SvsCapture(prepared) => {
                let results = crate::svs::samples::land(tx, bucket, prepared).await?;
                tracing::info!(
                    task = task.id.0,
                    root = %task.root,
                    write = "svs-capture",
                    captures = results.len(),
                    "write"
                );
            }
            Checked::RemediationCheck {
                probe,
                context,
                outcome,
            } => {
                let failed = |e: crate::actions::ActionError| match e {
                    crate::actions::ActionError::Db(e) => e,
                    other => DbError::Decode(format!(
                        "task {}'s remediation check by {probe}: {other}",
                        task.id
                    )),
                };
                let (check, new) = crate::actions::request_check(
                    tx,
                    stores.actions,
                    &crate::actions::NewCheck {
                        handler: probe,
                        observable_type: task.observable.kind.as_str(),
                        observable_value: &task.observable.value,
                        root: task.root,
                        context: context.as_ref(),
                    },
                )
                .await
                .map_err(failed)?;
                let recorded = match outcome {
                    Some(outcome) => {
                        crate::actions::record_outcome(tx, stores.actions, check, outcome)
                            .await
                            .map_err(failed)?
                    }
                    None => false,
                };
                tracing::info!(
                    task = task.id.0,
                    root = %task.root,
                    write = "remediation-check",
                    probe,
                    check,
                    new,
                    recorded,
                    "write"
                );
            }
        }
    }
    Ok(())
}

/// ace3's `record_thread`: the message, then each participant, each left as it was when it's
/// already recorded.
async fn record_thread(tx: &mut Tx<'_>, record: &ThreadRecord) -> Result<(), DbError> {
    let message_date = record
        .message_date
        .as_deref()
        .map(|date| {
            NaiveDateTime::parse_from_str(date, "%Y-%m-%d %H:%M:%S")
                .map_err(|e| DbError::Decode(format!("message_date {date:?}: {e}")))
        })
        .transpose()?;
    sqlx::query!(
        "INSERT INTO brocess.email_thread_message
             (thread_id, thread_id_hash, message_id, message_id_hash, in_reply_to,
              normalized_subject, normalized_subject_hash, from_address, from_domain, direction,
              message_date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (thread_id_hash, message_id_hash) DO NOTHING",
        record.thread_id,
        hash(&record.thread_id),
        record.message_id,
        hash(&record.message_id),
        record.in_reply_to,
        record.normalized_subject,
        record.normalized_subject.as_deref().map(hash),
        record.from_address,
        record.from_domain,
        record.direction,
        message_date,
    )
    .execute(tx.conn())
    .await?;
    for participant in &record.participants {
        let entry = [
            record.message_id.as_str(),
            &participant.domain,
            &participant.address,
            &participant.role,
        ]
        .join("\u{1f}");
        sqlx::query!(
            "INSERT INTO brocess.email_thread_domain
                 (thread_id, thread_id_hash, message_id_hash, domain, address, role, entry_hash,
                  numseen, firstseendate)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 1,
                     date_trunc('second', now() AT TIME ZONE 'UTC'))
             ON CONFLICT (thread_id_hash, entry_hash) DO NOTHING",
            record.thread_id,
            hash(&record.thread_id),
            hash(&record.message_id),
            participant.domain,
            participant.address,
            participant.role,
            hash(&entry),
        )
        .execute(tx.conn())
        .await?;
    }
    tracing::info!(
        thread = %record.thread_id,
        message = %record.message_id,
        participants = record.participants.len(),
        write = "email-thread",
        "write"
    );
    Ok(())
}
