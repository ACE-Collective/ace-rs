//! Ruleset builds (PLAN.md 2.25): the core compiles the signatures repository at each new
//! commit, puts the serialized ruleset in the bucket under its key, and writes its manifest
//! (`ace_yara::ruleset::Manifest`) as a row of `yara.rulesets`, which fixes ace3 #1051.
//!
//! The builder looks at the commit a revision names, `HEAD` by default, each time it runs. A
//! commit it has a row for is done. A commit whose signature directory is a tree an earlier
//! commit built gets a row of its own with that build's key and manifest, without compiling,
//! since the bytes would be the same. Anything else compiles from git's objects
//! (`ace_yara::ruleset::build_commit`), so the checkout's working tree doesn't matter and nothing
//! in the repository changes. A file that fails to compile is logged at ERROR with its path and
//! the commit, and left out. A commit between two runs that HEAD has already moved past isn't
//! built.
//!
//! The pools ask for the latest row (`current`) through the lease API and load its bytes from
//! the bucket (PLAN.md 2.26).
//!
//! A row also lists the rules in QA mode (`qa_rules`), which 5.6's `yara_qa` router serves. A row
//! built before that column has none, and the next run builds its commit again to fill it in: the
//! bytes come out the same, so the key and the pools don't change.

use std::path::PathBuf;
use std::time::Duration;

use ace_results::Sha256;
use ace_yara::LoadOptions;
pub use ace_yara::YARA_X_VERSION;
pub use ace_yara::ruleset::QaRule;
use ace_yara::ruleset::{self, BuildError, IncludedFile, LeftOutFile};
use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::bucket::{Bucket, BucketError};
use crate::db::{Db, DbError};

/// The bucket pool rulesets go in. It is permanent: a ruleset is small next to the files it
/// scans, and a row names it for as long as the row exists.
pub const RULESETS: &str = "yara_rulesets";

/// How long one build may take, compiling included.
pub const BUILD_TIMEOUT: Duration = Duration::from_secs(600);

/// The signatures repository and where its rules are in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRepo {
    /// The repository's checkout.
    pub repo: PathBuf,
    /// The revision to build, such as `HEAD` or `main`.
    pub rev: String,
    /// The signature directory, relative to the repository's top: one namespace per
    /// subdirectory.
    pub dir: PathBuf,
}

impl SignatureRepo {
    /// `yara` at `HEAD`, as the signatures repository holds it.
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        SignatureRepo {
            repo: repo.into(),
            rev: "HEAD".to_owned(),
            dir: PathBuf::from("yara"),
        }
    }

    /// The repository in `ACE4_SIGNATURES_REPO`, with `ACE4_SIGNATURES_REV` and
    /// `ACE4_SIGNATURES_DIR` overriding the revision and the directory. None when the first
    /// isn't set or is empty.
    pub fn from_env() -> Option<Self> {
        // set but empty is unset, as Compose's ${VAR:+...} leaves it when no repository is given
        let repo = std::env::var_os("ACE4_SIGNATURES_REPO").filter(|repo| !repo.is_empty())?;
        let mut repo = SignatureRepo::new(repo);
        if let Ok(rev) = std::env::var("ACE4_SIGNATURES_REV") {
            repo.rev = rev;
        }
        if let Some(dir) = std::env::var_os("ACE4_SIGNATURES_DIR") {
            repo.dir = dir.into();
        }
        Some(repo)
    }
}

/// A built ruleset's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetRow {
    pub id: i64,
    /// The sha256 of the serialized ruleset, its name in the `yara_rulesets` pool.
    pub key: Sha256,
    pub commit: String,
    pub tree: String,
    pub sources_sha256: String,
    pub yara_x_version: String,
    pub files: Vec<IncludedFile>,
    pub left_out: Vec<LeftOutFile>,
    /// The rules in QA mode, or None for a row built before they were recorded.
    pub qa_rules: Option<Vec<QaRule>>,
    pub built_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum RulesetError {
    #[error("building the ruleset: {0}")]
    Build(String),
    #[error("the build took longer than {0:?}")]
    TimedOut(Duration),
    #[error("{commit} has no directory {dir}")]
    NoDirectory { commit: String, dir: String },
    #[error(transparent)]
    Bucket(#[from] BucketError),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for RulesetError {
    fn from(error: sqlx::Error) -> Self {
        RulesetError::Db(DbError::Sqlx(error))
    }
}

impl From<BuildError> for RulesetError {
    fn from(error: BuildError) -> Self {
        RulesetError::Build(error.to_string())
    }
}

/// Runs blocking work, such as git or a compile, off the runtime, bounded by `BUILD_TIMEOUT`.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, BuildError> + Send + 'static,
) -> Result<T, RulesetError> {
    let span = tracing::Span::current();
    let joined = tokio::time::timeout(
        BUILD_TIMEOUT,
        tokio::task::spawn_blocking(move || span.in_scope(work)),
    )
    .await
    .map_err(|_| RulesetError::TimedOut(BUILD_TIMEOUT))?;
    match joined {
        Ok(result) => Ok(result?),
        Err(e) => Err(RulesetError::Build(format!("the build stopped: {e}"))),
    }
}

/// Builds the commit `repo.rev` names unless it has a row already, or one built before QA rules
/// were recorded, which this fills in. Returns the new or filled row, or None when there was
/// nothing to build.
pub async fn build_new(
    db: &Db,
    bucket: &Bucket,
    repo: &SignatureRepo,
) -> Result<Option<RulesetRow>, RulesetError> {
    let commit = {
        let (path, rev) = (repo.repo.clone(), repo.rev.clone());
        blocking(move || ruleset::resolve_commit(&path, &rev)).await?
    };
    let version = ace_yara::YARA_X_VERSION;
    let built = sqlx::query_scalar!(
        "SELECT id FROM yara.rulesets
         WHERE commit = $1 AND yara_x_version = $2 AND qa_rules IS NOT NULL",
        commit,
        version,
    )
    .fetch_optional(db.pool())
    .await?;
    if built.is_some() {
        return Ok(None);
    }
    let span = tracing::info_span!("ruleset_build", %commit);
    build_commit(db, bucket, repo, commit)
        .instrument(span)
        .await
        .map(Some)
}

async fn build_commit(
    db: &Db,
    bucket: &Bucket,
    repo: &SignatureRepo,
    commit: String,
) -> Result<RulesetRow, RulesetError> {
    let version = ace_yara::YARA_X_VERSION;
    let tree = {
        let (path, commit, dir) = (repo.repo.clone(), commit.clone(), repo.dir.clone());
        blocking(move || ruleset::tree_id(&path, &commit, &dir)).await?
    }
    .ok_or_else(|| RulesetError::NoDirectory {
        commit: commit.clone(),
        dir: repo.dir.display().to_string(),
    })?;

    // the same tree built before gives the same bytes, so its row's build serves this commit
    let earlier = sqlx::query!(
        r#"SELECT key, sources_sha256, files, left_out, qa_rules AS "qa_rules!" FROM yara.rulesets
           WHERE tree = $1 AND yara_x_version = $2 AND qa_rules IS NOT NULL
           ORDER BY id DESC LIMIT 1"#,
        tree,
        version,
    )
    .fetch_optional(db.pool())
    .await?;
    let (key, sources_sha256, files, left_out, qa_rules) = match earlier {
        Some(row) => {
            tracing::info!(key = %row.key, "the signature directory is unchanged since an earlier build");
            (
                row.key,
                row.sources_sha256,
                row.files,
                row.left_out,
                row.qa_rules,
            )
        }
        None => {
            let built = {
                let (path, commit, dir) = (repo.repo.clone(), commit.clone(), repo.dir.clone());
                blocking(move || {
                    ruleset::build_commit(&path, &commit, &dir, &LoadOptions::default())
                })
                .await?
            };
            let manifest = built.manifest;
            for file in &manifest.left_out {
                tracing::error!(
                    path = %file.path,
                    commit = %commit,
                    "a YARA rule file was left out of the ruleset: {}",
                    file.error
                );
            }
            let put = bucket.put_bytes(RULESETS, &built.bytes, None).await?;
            if put.object.sha256.to_hex() != manifest.key {
                return Err(RulesetError::Build(format!(
                    "the bucket named the ruleset {}, not its key {}",
                    put.object.sha256, manifest.key
                )));
            }
            let json = |value: serde_json::Result<serde_json::Value>| {
                value.map_err(|e| RulesetError::Build(format!("the manifest: {e}")))
            };
            (
                manifest.key,
                manifest.sources_sha256,
                json(serde_json::to_value(&manifest.files))?,
                json(serde_json::to_value(&manifest.left_out))?,
                json(serde_json::to_value(&manifest.qa_rules))?,
            )
        }
    };
    // a core on another node may have built the same commit meanwhile; a row from before QA
    // rules were recorded gets them, and keeps the rest
    sqlx::query!(
        "INSERT INTO yara.rulesets AS r
             (key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (commit, yara_x_version) DO UPDATE SET qa_rules = EXCLUDED.qa_rules
         WHERE r.qa_rules IS NULL",
        key,
        commit,
        tree,
        sources_sha256,
        version,
        files,
        left_out,
        qa_rules,
    )
    .execute(db.pool())
    .await?;
    let row = by_commit(db, &commit)
        .await?
        .ok_or_else(|| RulesetError::Build(format!("no row for {commit} after its build")))?;
    tracing::info!(
        key = %row.key,
        files = row.files.len(),
        left_out = row.left_out.len(),
        qa_rules = row.qa_rules.as_ref().map_or(0, Vec::len),
        "built the ruleset"
    );
    Ok(row)
}

/// A `yara.rulesets` row as it reads.
struct Record {
    id: i64,
    key: String,
    commit: String,
    tree: String,
    sources_sha256: String,
    yara_x_version: String,
    files: serde_json::Value,
    left_out: serde_json::Value,
    qa_rules: Option<serde_json::Value>,
    built_at: DateTime<Utc>,
}

impl Record {
    fn decode(self) -> Result<RulesetRow, DbError> {
        let id = self.id;
        let decode = |what: &str, e: String| DbError::Decode(format!("ruleset {id}: {what}: {e}"));
        Ok(RulesetRow {
            id,
            key: self
                .key
                .parse()
                .map_err(|e| decode("key", format!("{e}")))?,
            commit: self.commit,
            tree: self.tree,
            sources_sha256: self.sources_sha256,
            yara_x_version: self.yara_x_version,
            files: serde_json::from_value(self.files)
                .map_err(|e| decode("files", e.to_string()))?,
            left_out: serde_json::from_value(self.left_out)
                .map_err(|e| decode("left_out", e.to_string()))?,
            qa_rules: self
                .qa_rules
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| decode("qa_rules", e.to_string()))?,
            built_at: self.built_at,
        })
    }
}

/// The row of a commit built with this build's yara-x.
pub async fn by_commit(db: &Db, commit: &str) -> Result<Option<RulesetRow>, DbError> {
    sqlx::query_as!(
        Record,
        "SELECT id, key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules,
                built_at
         FROM yara.rulesets WHERE commit = $1 AND yara_x_version = $2",
        commit,
        ace_yara::YARA_X_VERSION,
    )
    .fetch_optional(db.pool())
    .await?
    .map(Record::decode)
    .transpose()
}

/// The ruleset the pools should scan with: the latest built with this build's yara-x, which
/// is the only one this build's pools can load.
pub async fn current(db: &Db) -> Result<Option<RulesetRow>, DbError> {
    current_with(db.pool()).await
}

/// `current`, on a connection or in a transaction the caller holds.
pub async fn current_with<'c>(
    executor: impl sqlx::PgExecutor<'c>,
) -> Result<Option<RulesetRow>, DbError> {
    sqlx::query_as!(
        Record,
        "SELECT id, key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules,
                built_at
         FROM yara.rulesets WHERE yara_x_version = $1 ORDER BY id DESC LIMIT 1",
        ace_yara::YARA_X_VERSION,
    )
    .fetch_optional(executor)
    .await?
    .map(Record::decode)
    .transpose()
}

/// Runs `build_new` every `interval` until `stop` fires. A failed build is logged and tried
/// again on the next run.
pub async fn run_builder(
    db: Db,
    bucket: Bucket,
    repo: SignatureRepo,
    interval: Duration,
    stop: CancellationToken,
) {
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            built = build_new(&db, &bucket, &repo) => {
                if let Err(e) = built {
                    tracing::error!(repo = %repo.repo.display(), "the ruleset build failed: {e}");
                }
            }
        }
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
    }
}
