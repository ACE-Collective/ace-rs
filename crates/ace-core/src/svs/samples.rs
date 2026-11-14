//! SVS's samples (PLAN.md 7.10 batch 2): ace3's `saq/svs/labels.py`, `capture.py` and `storage.py`, and the
//! values of `constants.py` they use. Migration 0048 holds the tables; `ace_service`'s `svs_samples` reads
//! them and takes the analysts' actions.
//!
//! **A sample** is one (file sha256, rule uuid) pair of `svs.yara_captures`, over every alert it was
//! captured from. Its label is never stored: it's aggregated when it's read from the effective verdicts
//! (7.14) of its **contributing detections**, on each alert a capture of the pair came from, the detections
//! of that rule on the file observable with that sha256. Each one with a verdict casts one vote of one
//! strength, its verdict source, and the strongest strength that has any vote decides:
//!
//! ```text
//! label(votes) =
//!     NULL, NULL              if no detection has a verdict
//!     tp, strength            if only TP votes at the strongest strength present
//!     fp, strength            if only FP votes there
//!     conflicted, strength    if both: the newest vote never silently wins
//! ```
//!
//! with explicit > inherited_single > inherited_multi. A detection without a verdict (an unclassified
//! alert, or one attributed to a test run that isn't reviewed) casts none, and so do a deleted alert's,
//! which are gone with it. The rule exists twice, as `aggregate_label` here and as migration 0048's
//! `svs.sample_label` and `svs.sample_label_source`, which `svs.samples` uses, and the tests hold the two to
//! agree. What differs from ace3: the same bytes under two names in one alert are one file observable here,
//! analyzed once, so they're one detection and one vote, where ace3 has a node and a vote for each name.
//!
//! **Capture.** The `svs_yara_sample_capture` module finds the candidates, one per (file, rule uuid) of a
//! YARA detection on the file, on an alert graded TP or FP that no unreviewed test run holds, and hands
//! them to the core as its `svs-capture` write (`reads.md`). The core checks them, then `prepare` reads the
//! file's bytes before the end's transaction and `land` writes the captures in it: the bytes copied from
//! the root's files into the `svs_samples` pool, held by the capture (`svs_capture`/<id>), and the row with
//! its match record. A capture whose bytes can't be had keeps its row as `missing`, which is counted per
//! rule and tried again on the alert's next disposition, as ace3's is on its next dispositioned pass:
//! `file` when the root's copy is gone or no longer has its sha256 and the pool doesn't have the bytes,
//! `storage` when the bucket refused them. A capture that has stored is left as it is unless it lacks its
//! match record and the module now has one. What differs from ace3:
//! - The capture is one transaction, the end's, so there's no `pending` row and nothing to undo: a file
//!   deleted from SVS (`svs.sample_deletions`) is checked for when the bytes are read and again under the
//!   sample's lock in the transaction (`lock_sample`), which the deletion takes too, so a capture that
//!   raced a deletion writes nothing, where ace3's removes what it wrote.
//! - The match record is the row's `record`, as 2.27's QA matches keep theirs, where ace3 puts it in its
//!   CAS pool by digest.
//! - ace4's bucket is one, shared by every node, so there's no node to record or to read the bytes from.
//! - The scanner's version is yara-x's (`ace_yara::YARA_X_VERSION`), where ace3 records yara-python's and
//!   yara_scanner's. The rule's content hash, which ace3 reads from its rule inventory, is left NULL: the
//!   ruleset (2.25) doesn't record one per rule, and batch 3's validation is what reads it.

use std::collections::BTreeMap;
use std::sync::Arc;

use ace_results::Sha256;
use ace_sdk::writes::SvsCaptureCandidate;
use ace_store::{Spooled, Store, StoreError};
use serde::Serialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::bucket::{ALERT_FILES, Bucket, BucketError, Hold};
use crate::db::{Db, DbError, Tx};

/// The bucket's pool for the samples' bytes, ace3's `svs.samples.pool`.
pub const SVS_SAMPLES: &str = "svs_samples";
/// The holder kind of every capture's hold; its id is the capture's row id.
pub const HOLDER_KIND: &str = "svs_capture";
/// ace3's `SIGNATURE_UUID_MAX_LENGTH`: a longer rule uuid isn't captured.
pub const MAX_RULE_UUID: usize = 36;
/// ace3's column widths, which a longer value is cut to.
const MAX_RULE_NAME: usize = 256;
const MAX_NAMESPACE: usize = 256;
const MAX_FILE_PATH: usize = 1024;
/// ace3's `SIGNATURE_VERSION_UNKNOWN`.
pub const SIGNATURE_VERSION_UNKNOWN: &str = "unknown";
/// The value of the Label filter that matches a sample with no label, ace3's `LABEL_FILTER_NONE`.
pub const LABEL_FILTER_NONE: &str = "none";

/// The hold a capture keeps on its file in `SVS_SAMPLES`.
pub fn capture_hold(capture: i64) -> Hold {
    Hold::new(HOLDER_KIND, capture.to_string())
}

/// Where a capture is: ace3's `CaptureState`, without `pending`, since a capture is one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    /// The file is held for it.
    Stored,
    /// It couldn't keep the file; its `MissingReason` says why.
    Missing,
}

impl CaptureState {
    pub fn as_str(self) -> &'static str {
        match self {
            CaptureState::Stored => "stored",
            CaptureState::Missing => "missing",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "stored" => Some(CaptureState::Stored),
            "missing" => Some(CaptureState::Missing),
            _ => None,
        }
    }
}

/// What a capture lacks: ace3's `MissingReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    /// The file was gone, or no longer had that sha256, and the pool didn't have it.
    File,
    /// Stored, but the match record was gone.
    MatchRecord,
    /// The bucket refused the bytes.
    Storage,
}

impl MissingReason {
    pub const ALL: [MissingReason; 3] = [
        MissingReason::File,
        MissingReason::MatchRecord,
        MissingReason::Storage,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            MissingReason::File => "file",
            MissingReason::MatchRecord => "match_record",
            MissingReason::Storage => "storage",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_str() == text)
    }
}

/// A sample's label: ace3's `LABEL_TP`, `LABEL_FP` and `LABEL_CONFLICTED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Tp,
    Fp,
    /// Votes of both verdicts at the strongest strength present.
    Conflicted,
}

impl Label {
    pub const ALL: [Label; 3] = [Label::Tp, Label::Fp, Label::Conflicted];

    pub fn as_str(self) -> &'static str {
        match self {
            Label::Tp => "tp",
            Label::Fp => "fp",
            Label::Conflicted => "conflicted",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|label| label.as_str() == text)
    }
}

/// The strength of a vote: the verdict source of the detection that cast it, strongest first, as
/// `ace_service`'s `VerdictSource` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    Explicit,
    InheritedSingle,
    InheritedMulti,
}

impl Strength {
    /// Strongest first, ace3's `STRENGTHS`.
    pub const ALL: [Strength; 3] = [
        Strength::Explicit,
        Strength::InheritedSingle,
        Strength::InheritedMulti,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Strength::Explicit => "explicit",
            Strength::InheritedSingle => "inherited_single",
            Strength::InheritedMulti => "inherited_multi",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|strength| strength.as_str() == text)
    }
}

/// The votes of a sample's contributing detections, per verdict and strength: ace3's `Votes`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Votes {
    pub tp_explicit: i64,
    pub fp_explicit: i64,
    pub tp_inherited_single: i64,
    pub fp_inherited_single: i64,
    pub tp_inherited_multi: i64,
    pub fp_inherited_multi: i64,
}

impl Votes {
    /// The TP and FP votes at one strength.
    pub fn at(&self, strength: Strength) -> (i64, i64) {
        match strength {
            Strength::Explicit => (self.tp_explicit, self.fp_explicit),
            Strength::InheritedSingle => (self.tp_inherited_single, self.fp_inherited_single),
            Strength::InheritedMulti => (self.tp_inherited_multi, self.fp_inherited_multi),
        }
    }
}

/// A sample's label and the strength that decided it, from its votes: the rule in Rust, ace3's
/// `aggregate_label`.
pub fn aggregate_label(votes: &Votes) -> (Option<Label>, Option<Strength>) {
    for strength in Strength::ALL {
        match votes.at(strength) {
            (tp, fp) if tp > 0 && fp > 0 => return (Some(Label::Conflicted), Some(strength)),
            (tp, _) if tp > 0 => return (Some(Label::Tp), Some(strength)),
            (_, fp) if fp > 0 => return (Some(Label::Fp), Some(strength)),
            _ => {}
        }
    }
    (None, None)
}

/// What a list shows of a match without its record: the rule, its meta and tags, and for each string
/// identifier how many times it matched and where first. ace3's `summarize_match_record`, over a
/// `ScanResult` as a YARA result keeps it, whose strings are `[offset, identifier, bytes]`.
pub fn summarize_match_record(record: &Value) -> Value {
    let mut strings: BTreeMap<String, (i64, Option<i64>)> = BTreeMap::new();
    let mut total = 0i64;
    for entry in record["strings"].as_array().into_iter().flatten() {
        let Some(parts) = entry.as_array().filter(|parts| parts.len() >= 2) else {
            continue;
        };
        let identifier = match &parts[1] {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let offset = parts[0].as_i64();
        total += 1;
        let summary = strings.entry(identifier).or_insert((0, None));
        summary.0 += 1;
        if let Some(offset) = offset
            && summary.1.is_none_or(|first| offset < first)
        {
            summary.1 = Some(offset);
        }
    }
    let field = |name: &str| record.get(name).cloned().unwrap_or(Value::Null);
    json!({
        "rule": field("rule"),
        "namespace": field("namespace"),
        "commit": field("commit"),
        "tags": record["tags"].as_array().cloned().unwrap_or_default(),
        "meta": record["meta"].as_object().cloned().unwrap_or_else(Map::new),
        "string_match_count": total,
        "strings": strings
            .into_iter()
            .map(|(identifier, (count, first_offset))| json!({
                "identifier": identifier,
                "count": count,
                "first_offset": first_offset,
            }))
            .collect::<Vec<_>>(),
    })
}

/// Takes the sample's lock for the rest of the transaction, so a capture and a deletion of the same
/// file never interleave: each sees the other's commit or none of it.
pub async fn lock_sample(tx: &mut Tx<'_>, sha256: &str) -> Result<(), DbError> {
    sqlx::query!(
        "SELECT pg_advisory_xact_lock(hashtextextended('svs_sample:' || $1, 0))",
        sha256,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Whether the file was deleted from SVS: it has a row in `svs.sample_deletions`.
pub async fn is_deleted(conn: &mut sqlx::PgConnection, sha256: &str) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT FROM svs.sample_deletions WHERE sha256 = $1) AS "deleted!""#,
        sha256,
    )
    .fetch_one(conn)
    .await?)
}

/// What a capture did: ace3's `CaptureStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    /// The file is now held for this capture.
    Stored,
    /// It already was.
    Already,
    /// It couldn't be; the row says why.
    Missing,
    /// The file was deleted from SVS; there's no row.
    Deleted,
}

/// A capture's outcome and its row, which a deleted file has none of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CaptureResult {
    pub status: CaptureStatus,
    pub capture: Option<i64>,
}

/// Where a capture's bytes come from, as `prepare` found them.
#[derive(Debug, Clone)]
enum Bytes {
    /// Read from the root's copy, to put in the pool.
    Spooled(Arc<Spooled>),
    /// The pool has them already: only a hold is taken.
    Held,
    /// Neither the root's copy nor the pool has them, and why.
    Gone(String),
    /// Reading the root's copy failed.
    Unreadable(String),
    /// Nothing to do: stored already, or deleted from SVS.
    Skip(CaptureStatus),
}

/// One candidate, checked and with its bytes found, for `land`.
#[derive(Debug, Clone)]
pub struct Prepared {
    root: Uuid,
    observable: Option<i64>,
    candidate: SvsCaptureCandidate,
    bytes: Bytes,
}

/// What `prepare` reads of a capture that's there.
struct Existing {
    state: String,
    missing_reason: Option<String>,
}

async fn existing(
    conn: &mut sqlx::PgConnection,
    root: Uuid,
    candidate: &SvsCaptureCandidate,
    lock: bool,
) -> Result<Option<Existing>, DbError> {
    let row = if lock {
        sqlx::query!(
            "SELECT state, missing_reason FROM svs.yara_captures
             WHERE root_id = $1 AND sha256 = $2 AND rule_uuid = $3 FOR UPDATE",
            root,
            candidate.sha256,
            candidate.rule_uuid,
        )
        .fetch_optional(conn)
        .await?
        .map(|row| Existing {
            state: row.state,
            missing_reason: row.missing_reason,
        })
    } else {
        sqlx::query!(
            "SELECT state, missing_reason FROM svs.yara_captures
             WHERE root_id = $1 AND sha256 = $2 AND rule_uuid = $3",
            root,
            candidate.sha256,
            candidate.rule_uuid,
        )
        .fetch_optional(conn)
        .await?
        .map(|row| Existing {
            state: row.state,
            missing_reason: row.missing_reason,
        })
    };
    Ok(row)
}

/// Whether a capture that's there is done with: it stored, and it has its match record or the
/// candidate has none to add. ace3 tries again only to add a match record it didn't have.
fn already(existing: &Existing, candidate: &SvsCaptureCandidate) -> bool {
    existing.state == CaptureState::Stored.as_str()
        && (existing.missing_reason.as_deref() != Some(MissingReason::MatchRecord.as_str())
            || candidate.match_record.is_none())
}

fn describe(candidate: &SvsCaptureCandidate) -> String {
    format!(
        "{} ({}) for rule {} ({})",
        candidate.file_path, candidate.sha256, candidate.rule_name, candidate.rule_uuid
    )
}

/// Finds each candidate's bytes before the end's transaction, as ace3's `capture` does before its puts:
/// the pool's copy when it has one (a hold is all that's needed), else the root's copy in `alert_files`,
/// checked against its sha256. A candidate stored already, or of a file deleted from SVS, needs nothing.
/// `root` and `observable` are the task's.
pub async fn prepare(
    db: &Db,
    bucket: &Bucket,
    root: Uuid,
    observable: Option<i64>,
    candidates: Vec<SvsCaptureCandidate>,
) -> Result<Vec<Prepared>, DbError> {
    let mut prepared = Vec::with_capacity(candidates.len());
    // one read of the bytes per file, whatever the number of rules that matched it
    let mut found: BTreeMap<String, Bytes> = BTreeMap::new();
    for candidate in candidates {
        let mut conn = db.pool().acquire().await?;
        let bytes = if is_deleted(&mut conn, &candidate.sha256).await? {
            tracing::info!(
                root = %root,
                sha256 = %candidate.sha256,
                rule_uuid = %candidate.rule_uuid,
                "svs sample {} of alert {root} was deleted from svs; it is not captured again",
                describe(&candidate)
            );
            Bytes::Skip(CaptureStatus::Deleted)
        } else if existing(&mut conn, root, &candidate, false)
            .await?
            .is_some_and(|row| already(&row, &candidate))
        {
            Bytes::Skip(CaptureStatus::Already)
        } else if let Some(bytes) = found.get(&candidate.sha256) {
            bytes.clone()
        } else {
            drop(conn);
            let bytes = find_bytes(bucket, &candidate.sha256).await?;
            found.insert(candidate.sha256.clone(), bytes.clone());
            bytes
        };
        prepared.push(Prepared {
            root,
            observable,
            candidate,
            bytes,
        });
    }
    Ok(prepared)
}

async fn find_bytes(bucket: &Bucket, sha256: &str) -> Result<Bytes, DbError> {
    let Ok(parsed) = sha256.parse::<Sha256>() else {
        return Ok(Bytes::Gone(format!("{sha256:?} isn't a sha256")));
    };
    let held = bucket
        .object(SVS_SAMPLES, &parsed)
        .await
        .map_err(bucket_db_error)?;
    if held.is_some() {
        return Ok(Bytes::Held);
    }
    let key = match Store::key(ALERT_FILES, &parsed) {
        Ok(key) => key,
        Err(e) => return Ok(Bytes::Unreadable(e.to_string())),
    };
    Ok(match bucket.store().spool_key(&key, &parsed).await {
        Ok(spooled) => Bytes::Spooled(Arc::new(spooled)),
        Err(StoreError::NotFound { .. }) => Bytes::Gone("its file is gone".to_owned()),
        // the file the root has isn't the one the detection names: it was hashed before it was whole,
        // or written again since
        Err(StoreError::Integrity { actual, .. }) => {
            Bytes::Gone(format!("its file now hashes to {actual}"))
        }
        Err(e) => Bytes::Unreadable(e.to_string()),
    })
}

fn bucket_db_error(error: BucketError) -> DbError {
    match error {
        BucketError::Db(e) => e,
        other => DbError::Decode(format!("the bucket's index: {other}")),
    }
}

fn cut(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

/// Writes the prepared captures in the end's transaction, each under its sample's lock: ace3's `capture`
/// for each candidate. A capture whose bytes the bucket refuses is `missing` with `storage`, in a
/// savepoint, so it doesn't fail the others or the end.
pub async fn land(
    tx: &mut Tx<'_>,
    bucket: &Bucket,
    prepared: &[Prepared],
) -> Result<Vec<CaptureResult>, DbError> {
    let mut results = Vec::with_capacity(prepared.len());
    for item in prepared {
        results.push(land_one(tx, bucket, item).await?);
    }
    Ok(results)
}

async fn land_one(
    tx: &mut Tx<'_>,
    bucket: &Bucket,
    item: &Prepared,
) -> Result<CaptureResult, DbError> {
    let candidate = &item.candidate;
    let root = item.root;
    let sha256 = candidate.sha256.as_str();
    let rule_uuid = candidate.rule_uuid.as_str();
    if let Bytes::Skip(status) = item.bytes {
        let capture = if status == CaptureStatus::Already {
            capture_id(tx, root, candidate).await?
        } else {
            None
        };
        return Ok(CaptureResult { status, capture });
    }
    lock_sample(tx, sha256).await?;
    // a deletion that committed since `prepare` read the bytes
    if is_deleted(tx.conn(), sha256).await? {
        tracing::info!(
            root = %root,
            sha256 = %sha256,
            rule_uuid = %rule_uuid,
            "svs sample {} of alert {root} was deleted from svs while it was captured; nothing is written",
            describe(candidate)
        );
        return Ok(CaptureResult {
            status: CaptureStatus::Deleted,
            capture: None,
        });
    }
    let before = existing(tx.conn(), root, candidate, true).await?;
    if let Some(row) = &before
        && already(row, candidate)
    {
        return Ok(CaptureResult {
            status: CaptureStatus::Already,
            capture: capture_id(tx, root, candidate).await?,
        });
    }
    let was_missing = before
        .as_ref()
        .is_some_and(|row| row.state == CaptureState::Missing.as_str());
    let newly_stored = before
        .as_ref()
        .is_none_or(|row| row.state != CaptureState::Stored.as_str());
    let yara_meta_tags = &candidate.yara_meta_tags;
    // the row's id is its hold's; a missing capture keeps its row, with why
    let id = sqlx::query_scalar!(
        "INSERT INTO svs.yara_captures
             (root_id, observable_id, sha256, rule_uuid, rule_name, namespace, signature_version,
              file_path, yara_meta_tags, state, missing_reason)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'missing', 'file')
         ON CONFLICT (root_id, sha256, rule_uuid) DO UPDATE
         SET observable_id = excluded.observable_id, rule_name = excluded.rule_name,
             namespace = excluded.namespace, signature_version = excluded.signature_version,
             file_path = excluded.file_path, yara_meta_tags = excluded.yara_meta_tags
         RETURNING id",
        root,
        item.observable,
        sha256,
        rule_uuid,
        cut(&candidate.rule_name, MAX_RULE_NAME),
        candidate
            .namespace
            .as_deref()
            .map(|n| cut(n, MAX_NAMESPACE)),
        candidate.signature_version,
        cut(&candidate.file_path, MAX_FILE_PATH),
        yara_meta_tags,
    )
    .fetch_one(tx.conn())
    .await?;
    let hold = capture_hold(id);
    let size = match &item.bytes {
        Bytes::Spooled(spooled) => {
            let mut savepoint = tx.savepoint().await?;
            match bucket
                .put_in(&mut savepoint, SVS_SAMPLES, spooled, Some(&hold))
                .await
            {
                Ok(_) => {
                    savepoint.commit().await?;
                    Some(spooled.size)
                }
                Err(e) => {
                    savepoint.rollback().await?;
                    return set_missing(
                        tx,
                        id,
                        candidate,
                        root,
                        MissingReason::Storage,
                        &e.to_string(),
                        was_missing,
                    )
                    .await;
                }
            }
        }
        Bytes::Held => {
            let parsed: Sha256 = sha256
                .parse()
                .map_err(|e| DbError::Decode(format!("sha256 {sha256}: {e}")))?;
            let mut savepoint = tx.savepoint().await?;
            match bucket
                .hold_in(&mut savepoint, SVS_SAMPLES, &parsed, &hold)
                .await
            {
                Ok(()) => {
                    savepoint.commit().await?;
                    bucket
                        .object(SVS_SAMPLES, &parsed)
                        .await
                        .map_err(bucket_db_error)?
                        .map(|object| object.size)
                }
                // the pool's copy went since `prepare` found it
                Err(BucketError::NotFound { .. } | BucketError::Deleting { .. }) => {
                    savepoint.rollback().await?;
                    return set_missing(
                        tx,
                        id,
                        candidate,
                        root,
                        MissingReason::File,
                        "its file is gone",
                        was_missing,
                    )
                    .await;
                }
                Err(e) => {
                    savepoint.rollback().await?;
                    return set_missing(
                        tx,
                        id,
                        candidate,
                        root,
                        MissingReason::Storage,
                        &e.to_string(),
                        was_missing,
                    )
                    .await;
                }
            }
        }
        Bytes::Gone(problem) => {
            return set_missing(
                tx,
                id,
                candidate,
                root,
                MissingReason::File,
                problem,
                was_missing,
            )
            .await;
        }
        Bytes::Unreadable(problem) => {
            return set_missing(
                tx,
                id,
                candidate,
                root,
                MissingReason::Storage,
                problem,
                was_missing,
            )
            .await;
        }
        Bytes::Skip(_) => unreachable!("returned above"),
    };
    let summary = candidate.match_record.as_ref().map(summarize_match_record);
    let missing_reason = candidate
        .match_record
        .is_none()
        .then_some(MissingReason::MatchRecord.as_str());
    sqlx::query!(
        "UPDATE svs.yara_captures
         SET state = 'stored', missing_reason = $2, record = $3, match_summary = $4,
             file_size = $5, yara_version = $6, stored_at = COALESCE(stored_at, now())
         WHERE id = $1",
        id,
        missing_reason,
        candidate.match_record,
        summary,
        size.map(|size| i64::try_from(size).unwrap_or(i64::MAX)),
        ace_yara::YARA_X_VERSION,
    )
    .execute(tx.conn())
    .await?;
    if candidate.match_record.is_none() {
        tracing::error!(
            root = %root,
            sha256 = %sha256,
            rule_uuid = %rule_uuid,
            missing_reason = MissingReason::MatchRecord.as_str(),
            "captured svs sample {} of alert {root} without its match record (the alert's yara result doesn't have it)",
            describe(candidate)
        );
    }
    if candidate.signature_version == SIGNATURE_VERSION_UNKNOWN && newly_stored {
        tracing::error!(
            root = %root,
            sha256 = %sha256,
            rule_uuid = %rule_uuid,
            "captured svs sample {} of alert {root} with an unknown signature version",
            describe(candidate)
        );
    }
    tracing::info!(
        root = %root,
        sha256 = %sha256,
        rule_uuid = %rule_uuid,
        capture = id,
        "captured svs sample {} of alert {root} as {id}",
        describe(candidate)
    );
    Ok(CaptureResult {
        status: CaptureStatus::Stored,
        capture: Some(id),
    })
}

async fn capture_id(
    tx: &mut Tx<'_>,
    root: Uuid,
    candidate: &SvsCaptureCandidate,
) -> Result<Option<i64>, DbError> {
    Ok(sqlx::query_scalar!(
        "SELECT id FROM svs.yara_captures WHERE root_id = $1 AND sha256 = $2 AND rule_uuid = $3",
        root,
        candidate.sha256,
        candidate.rule_uuid,
    )
    .fetch_optional(tx.conn())
    .await?)
}

/// Marks a capture `missing`, releasing any hold it took, and reports it unless it was missing already,
/// as ace3's `_log_missing` and its storage failure do.
async fn set_missing(
    tx: &mut Tx<'_>,
    id: i64,
    candidate: &SvsCaptureCandidate,
    root: Uuid,
    reason: MissingReason,
    problem: &str,
    was_missing: bool,
) -> Result<CaptureResult, DbError> {
    sqlx::query!(
        "UPDATE svs.yara_captures
         SET state = 'missing', missing_reason = $2, record = NULL, match_summary = NULL,
             stored_at = NULL
         WHERE id = $1",
        id,
        reason.as_str(),
    )
    .execute(tx.conn())
    .await?;
    // a stored capture tried again for its record holds the file already
    if let Ok(parsed) = candidate.sha256.parse::<Sha256>() {
        crate::bucket::release_in(tx, SVS_SAMPLES, &parsed, &capture_hold(id))
            .await
            .map_err(bucket_db_error)?;
    }
    let (sha256, rule_uuid) = (&candidate.sha256, &candidate.rule_uuid);
    if was_missing {
        tracing::info!(
            root = %root,
            sha256 = %sha256,
            rule_uuid = %rule_uuid,
            missing_reason = reason.as_str(),
            "svs sample {} of alert {root} is still missing ({}: {problem})",
            describe(candidate),
            reason.as_str()
        );
    } else if reason == MissingReason::Storage {
        tracing::error!(
            root = %root,
            sha256 = %sha256,
            rule_uuid = %rule_uuid,
            missing_reason = reason.as_str(),
            "unable to store svs capture {} of alert {root}: {problem}",
            describe(candidate)
        );
    } else {
        tracing::error!(
            root = %root,
            sha256 = %sha256,
            rule_uuid = %rule_uuid,
            missing_reason = reason.as_str(),
            "unable to capture svs sample {} of alert {root}: {problem}",
            describe(candidate)
        );
    }
    Ok(CaptureResult {
        status: CaptureStatus::Missing,
        capture: Some(id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn votes(pairs: &[(&str, i64)]) -> Votes {
        let mut votes = Votes::default();
        for (name, count) in pairs {
            let slot = match *name {
                "tp_explicit" => &mut votes.tp_explicit,
                "fp_explicit" => &mut votes.fp_explicit,
                "tp_inherited_single" => &mut votes.tp_inherited_single,
                "fp_inherited_single" => &mut votes.fp_inherited_single,
                "tp_inherited_multi" => &mut votes.tp_inherited_multi,
                "fp_inherited_multi" => &mut votes.fp_inherited_multi,
                other => panic!("no vote {other}"),
            };
            *slot = *count;
        }
        votes
    }

    /// test_labels.py's `test_aggregate_label`, every case of its table.
    #[test]
    fn aggregate_label_follows_the_strongest_votes() {
        use Label::{Conflicted, Fp, Tp};
        use Strength::{Explicit, InheritedMulti, InheritedSingle};
        type Case<'a> = (&'a [(&'a str, i64)], (Option<Label>, Option<Strength>));
        let cases: &[Case] = &[
            (&[], (None, None)),
            (
                &[("tp_inherited_multi", 3)],
                (Some(Tp), Some(InheritedMulti)),
            ),
            (
                &[("fp_inherited_single", 1)],
                (Some(Fp), Some(InheritedSingle)),
            ),
            (
                &[("tp_inherited_single", 1), ("fp_inherited_single", 1)],
                (Some(Conflicted), Some(InheritedSingle)),
            ),
            // a stronger vote decides, whatever the number of weaker ones
            (
                &[
                    ("fp_explicit", 1),
                    ("tp_inherited_single", 5),
                    ("tp_inherited_multi", 5),
                ],
                (Some(Fp), Some(Explicit)),
            ),
            (
                &[("fp_inherited_single", 1), ("tp_inherited_multi", 9)],
                (Some(Fp), Some(InheritedSingle)),
            ),
            // disagreement below the deciding strength doesn't matter
            (
                &[
                    ("tp_explicit", 1),
                    ("tp_inherited_multi", 1),
                    ("fp_inherited_multi", 1),
                ],
                (Some(Tp), Some(Explicit)),
            ),
            (
                &[("tp_explicit", 2), ("fp_explicit", 1)],
                (Some(Conflicted), Some(Explicit)),
            ),
        ];
        for (pairs, expected) in cases {
            assert_eq!(aggregate_label(&votes(pairs)), *expected, "{pairs:?}");
        }
    }

    /// ace3's `summarize_match_record` over strings as an alert saved them: three hits of two strings.
    #[test]
    fn a_match_record_is_summarized() {
        let record = json!({
            "rule": "svs_rule", "namespace": "unittest", "commit": "c", "tags": ["t"],
            "meta": {"uuid": "u"},
            "strings": [[10, "$a", "abc"], [0, "$a", "abc"], [5, "$b", "\u{0}x"], "not a string"],
        });
        let summary = summarize_match_record(&record);
        assert_eq!(summary["string_match_count"], 3);
        assert_eq!(
            summary["strings"],
            json!([
                {"identifier": "$a", "count": 2, "first_offset": 0},
                {"identifier": "$b", "count": 1, "first_offset": 5},
            ])
        );
        assert_eq!(summary["rule"], "svs_rule");
        assert_eq!(summary["meta"], json!({"uuid": "u"}));
        assert_eq!(summary["tags"], json!(["t"]));
    }

    #[test]
    fn the_names_are_ace3_s() {
        assert_eq!(
            MissingReason::ALL.map(MissingReason::as_str),
            ["file", "match_record", "storage"]
        );
        assert_eq!(Label::ALL.map(Label::as_str), ["tp", "fp", "conflicted"]);
        assert_eq!(
            Strength::ALL.map(Strength::as_str),
            ["explicit", "inherited_single", "inherited_multi"]
        );
        assert_eq!(capture_hold(7), Hold::new("svs_capture", "7"));
    }
}
