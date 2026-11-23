//! The corpus a validation replays: every stored SVS capture, with the labels of its samples. ace3's
//! `saq/svs/yara/corpus.py`.
//!
//! A **unit** is one way a file was scanned: a distinct (sha256, file path, yara_meta tags) over the stored
//! captures. The path decides the `filename`, `filepath` and `extension` externals and the `file_ext` and
//! `file_name` filters, and the tags decide the `meta_tags` filters, so the same bytes captured under two
//! names are scanned twice, and a rule matches the file if it matches any of its units.
//!
//! A **sample** is one (sha256, rule uuid) and carries its label (`svs.samples`, batch 2). The samples and
//! the units are read in one repeatable-read transaction, so the labels are those of the same moment.
//!
//! Each unit is written to `<files_root>/<n>/files/<file_path>`, the tail of the path the file had in its
//! alert, by copying out of the bucket's `svs_samples` pool. A second unit of the same bytes is a hard link
//! to the first copy, never to the node's cache, which the scan could then change. A path that is absolute
//! or climbs out with `..` isn't replayed.
//!
//! **Bounds** (new in ace-rs): a corpus with more than `max_files` distinct files or `max_bytes` of them fails
//! the validation once it reaches that, rather than leaving samples out of a report that would read as
//! complete. ace3's `wrong_node` has no counterpart: the bucket is one, shared by every node.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ace_results::Sha256;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::bucket::Bucket;
use crate::db::{Db, DbError};
use crate::svs::samples::SVS_SAMPLES;

/// A capture's `file_path` is cut at this length when it's stored.
pub const FILE_PATH_MAX_LENGTH: usize = 1024;

pub const SKIP_UNSAFE_PATH: &str = "unsafe_path";
pub const SKIP_UNREADABLE: &str = "unreadable";

/// One (sha256, rule uuid) with its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub sha256: String,
    pub rule_uuid: String,
    pub rule_name: String,
    pub label: Option<String>,
    pub label_source: Option<String>,
}

/// One way a file was scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub id: u64,
    pub sha256: String,
    pub file_path: String,
    pub meta_tags: Vec<String>,
    /// Where it was written, once it was.
    pub path: Option<PathBuf>,
    /// The stored path was cut at `FILE_PATH_MAX_LENGTH`, so the path externals may differ.
    pub truncated: bool,
}

/// A unit that wasn't replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub sha256: String,
    pub file_path: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct Corpus {
    pub samples: BTreeMap<(String, String), Sample>,
    pub units: Vec<Unit>,
    pub skipped: Vec<Skipped>,
    /// The bytes of the files written.
    pub bytes: u64,
}

impl Corpus {
    /// The files at least one unit of which was written.
    pub fn replayed_sha256s(&self) -> BTreeSet<String> {
        self.units
            .iter()
            .filter(|u| u.path.is_some())
            .map(|u| u.sha256.clone())
            .collect()
    }
}

/// How much of the corpus a validation may copy out of the bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusLimits {
    pub max_files: u64,
    pub max_bytes: u64,
}

/// Why the corpus couldn't be written.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("{0}")]
    TooLarge(String),
    #[error("the validation was cancelled")]
    Cancelled,
}

/// Whether a capture's path may be written below the unit's directory.
pub fn is_safe_path(file_path: &str) -> bool {
    !file_path.is_empty()
        && !file_path.contains('\0')
        && !file_path.starts_with('/')
        && !file_path.split('/').any(|part| part == "..")
}

/// Every stored unit and every sample of a stored file, in one transaction, with the labels under the
/// dispositions' classes `tp` and `fp`.
pub async fn read_corpus(db: &Db, tp: &[String], fp: &[String]) -> Result<Corpus, DbError> {
    let mut tx = db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(tx.conn())
        .await?;
    let rows: Vec<(String, String, Vec<String>)> = sqlx::query_as(
        "SELECT sha256, file_path, yara_meta_tags FROM svs.yara_captures
         WHERE state = 'stored' ORDER BY id",
    )
    .fetch_all(tx.conn())
    .await?;
    type SampleRow = (String, String, String, Option<String>, Option<String>);
    let samples: Vec<SampleRow> = sqlx::query_as(
        "SELECT sha256, rule_uuid, rule_name, label, label_source FROM svs.samples($1, $2, NULL)",
    )
    .bind(tp)
    .bind(fp)
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;

    let mut corpus = Corpus::default();
    let mut seen = BTreeSet::new();
    let mut stored = BTreeSet::new();
    for (sha256, file_path, meta_tags) in rows {
        stored.insert(sha256.clone());
        if !seen.insert((sha256.clone(), file_path.clone(), meta_tags.clone())) {
            continue;
        }
        corpus.units.push(Unit {
            id: corpus.units.len() as u64,
            truncated: file_path.chars().count() >= FILE_PATH_MAX_LENGTH,
            sha256,
            file_path,
            meta_tags,
            path: None,
        });
    }
    for (sha256, rule_uuid, rule_name, label, label_source) in samples {
        if stored.contains(&sha256) {
            corpus.samples.insert(
                (sha256.clone(), rule_uuid.clone()),
                Sample {
                    sha256,
                    rule_uuid,
                    rule_name,
                    label,
                    label_source,
                },
            );
        }
    }
    Ok(corpus)
}

/// Writes every unit the bucket has under `files_root`, recording the rest in `corpus.skipped`. Stops with
/// `Cancelled` soon after `cancel` is set, and with `TooLarge` at the limits.
pub async fn write_units(
    corpus: &mut Corpus,
    bucket: &Bucket,
    files_root: &Path,
    limits: CorpusLimits,
    cancel: &CancellationToken,
) -> Result<(), CorpusError> {
    let mut written: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut refused: BTreeSet<String> = BTreeSet::new();
    let mut skipped = Vec::new();
    for unit in &mut corpus.units {
        if cancel.is_cancelled() {
            return Err(CorpusError::Cancelled);
        }
        if refused.contains(&unit.sha256) {
            continue;
        }
        if !is_safe_path(&unit.file_path) {
            skipped.push(Skipped {
                sha256: unit.sha256.clone(),
                file_path: Some(unit.file_path.clone()),
                reason: SKIP_UNSAFE_PATH.to_owned(),
                detail: String::new(),
            });
            continue;
        }

        let dest = files_root
            .join(unit.id.to_string())
            .join("files")
            .join(&unit.file_path);
        let outcome = match written.get(&unit.sha256) {
            Some(source) => link(source, &dest).await,
            None => {
                if written.len() as u64 >= limits.max_files {
                    return Err(CorpusError::TooLarge(format!(
                        "the corpus has more than {} files (svs.yara.max_corpus_files)",
                        limits.max_files
                    )));
                }
                copy_out(bucket, &unit.sha256, &dest, corpus.bytes, limits.max_bytes).await
            }
        };
        match outcome {
            Ok(Copied::Linked) => {}
            Ok(Copied::Bytes(size)) => {
                corpus.bytes += size;
                written.insert(unit.sha256.clone(), dest.clone());
            }
            Ok(Copied::TooLarge) => {
                return Err(CorpusError::TooLarge(format!(
                    "the corpus is larger than {} bytes (svs.yara.max_corpus_bytes)",
                    limits.max_bytes
                )));
            }
            Err(e) => {
                tracing::warn!(sha256 = %unit.sha256, "unable to replay an svs sample: {e}");
                if !written.contains_key(&unit.sha256) {
                    refused.insert(unit.sha256.clone());
                }
                skipped.push(Skipped {
                    sha256: unit.sha256.clone(),
                    file_path: Some(unit.file_path.clone()),
                    reason: SKIP_UNREADABLE.to_owned(),
                    detail: e,
                });
                continue;
            }
        }
        unit.path = Some(dest);
    }
    corpus.skipped.extend(skipped);
    Ok(())
}

enum Copied {
    Linked,
    Bytes(u64),
    TooLarge,
}

async fn link(source: &Path, dest: &Path) -> Result<Copied, String> {
    let (source, dest) = (source.to_path_buf(), dest.to_path_buf());
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::hard_link(&source, &dest)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    Ok(Copied::Linked)
}

async fn copy_out(
    bucket: &Bucket,
    sha256: &str,
    dest: &Path,
    so_far: u64,
    max_bytes: u64,
) -> Result<Copied, String> {
    let parsed: Sha256 = sha256.parse().map_err(|_| "not a sha256".to_owned())?;
    let cached = bucket
        .get(SVS_SAMPLES, &parsed)
        .await
        .map_err(|e| e.to_string())?;
    if so_far.saturating_add(cached.size) > max_bytes {
        return Ok(Copied::TooLarge);
    }
    let dest = dest.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::io::Result<u64> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = cached.file;
        let mut out = std::fs::File::create(&dest)?;
        std::io::copy(&mut file, &mut out)
    })
    .await
    .map_err(|e| e.to_string())?
    .map(Copied::Bytes)
    .map_err(|e| e.to_string())
}
