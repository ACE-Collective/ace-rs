//! The alert tree in Postgres: roots, their observables and the results about them.
//!
//! An observable is unique on (root, type, value), so adding one that is already there merges
//! its tags, directives, excluded modules and relationships into the existing row. A result is
//! unique on (root, observable, module).

use ace_results::types::email::EmailAnalysis;
use ace_results::{
    AnalysisType, Detection, NewObservable, ObservableAdditions, ObservableKind, ObservableRef,
    ResultEnvelope,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::db::{DbError, Tx};

/// Where a root's event time came from (ace3 #850).
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "analysis.event_time_source", rename_all = "snake_case")]
pub enum EventTimeSource {
    Event,
    QueryTime,
    Now,
    Unset,
}

/// A root's event time, with where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTime {
    /// When the event happened, as the submitter knew it, such as an S3 event's time.
    Event(DateTime<Utc>),
    /// A hunt's query time, used when a result had no time of its own.
    QueryTime(DateTime<Utc>),
    /// The time ACE substituted because the submitter gave none.
    Now(DateTime<Utc>),
    Unset,
}

impl EventTime {
    pub fn time(self) -> Option<DateTime<Utc>> {
        match self {
            EventTime::Event(t) | EventTime::QueryTime(t) | EventTime::Now(t) => Some(t),
            EventTime::Unset => None,
        }
    }

    pub fn source(self) -> EventTimeSource {
        match self {
            EventTime::Event(_) => EventTimeSource::Event,
            EventTime::QueryTime(_) => EventTimeSource::QueryTime,
            EventTime::Now(_) => EventTimeSource::Now,
            EventTime::Unset => EventTimeSource::Unset,
        }
    }

    fn from_parts(time: Option<DateTime<Utc>>, source: EventTimeSource) -> Result<Self, DbError> {
        match (source, time) {
            (EventTimeSource::Event, Some(t)) => Ok(EventTime::Event(t)),
            (EventTimeSource::QueryTime, Some(t)) => Ok(EventTime::QueryTime(t)),
            (EventTimeSource::Now, Some(t)) => Ok(EventTime::Now(t)),
            (EventTimeSource::Unset, None) => Ok(EventTime::Unset),
            (source, time) => Err(DbError::Decode(format!(
                "event time {time:?} with source {source:?}"
            ))),
        }
    }
}

/// A root to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRoot {
    pub id: Uuid,
    pub analysis_mode: String,
    pub description: String,
    pub event_time: EventTime,
}

impl NewRoot {
    /// A root with a new id, in `analysis_mode`, whose event time is now.
    pub fn new(analysis_mode: impl Into<String>) -> Self {
        NewRoot {
            id: Uuid::new_v4(),
            analysis_mode: analysis_mode.into(),
            description: String::new(),
            event_time: EventTime::Now(Utc::now()),
        }
    }
}

/// A root as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub id: Uuid,
    pub analysis_mode: String,
    pub description: String,
    pub event_time: EventTime,
    pub created_at: DateTime<Utc>,
}

/// An observable's row id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, sqlx::Type)]
#[sqlx(transparent)]
pub struct ObservableId(pub i64);

/// A result's row id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, sqlx::Type)]
#[sqlx(transparent)]
pub struct ResultId(pub i64);

/// What upserting an observable did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upserted {
    pub id: ObservableId,
    /// False when the observable was already in the root and the new one merged into it.
    pub inserted: bool,
}

/// An observable as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observable {
    pub id: ObservableId,
    pub root: Uuid,
    pub kind: ObservableKind,
    pub value: String,
    pub time: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub directives: Vec<String>,
    pub exclude_modules: Vec<String>,
}

pub async fn create_root(tx: &mut Tx<'_>, root: &NewRoot) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO analysis.roots (id, analysis_mode, description, event_time, event_time_source)
         VALUES ($1, $2, $3, $4, $5)",
        root.id,
        root.analysis_mode,
        root.description,
        root.event_time.time(),
        root.event_time.source() as EventTimeSource,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

pub async fn root<'e>(executor: impl PgExecutor<'e>, id: Uuid) -> Result<Option<Root>, DbError> {
    let row = sqlx::query!(
        r#"SELECT id, analysis_mode, description, event_time,
                  event_time_source AS "event_time_source: EventTimeSource", created_at
           FROM analysis.roots WHERE id = $1"#,
        id,
    )
    .fetch_optional(executor)
    .await?;
    row.map(|row| {
        Ok(Root {
            id: row.id,
            analysis_mode: row.analysis_mode,
            description: row.description,
            event_time: EventTime::from_parts(row.event_time, row.event_time_source)?,
            created_at: row.created_at,
        })
    })
    .transpose()
}

/// Adds an observable to a root, or merges it into the one with the same type and value: the
/// stored time is kept if it has one, and tags, directives, excluded modules and relationships it
/// lacks are added. Of two redirections the lowest is kept, so a tree doesn't depend on which task
/// ended first: a macro in a `.docm` is in the `.docm` and in the `vbaProject.bin` taken out of it,
/// each redirecting to where it was found.
pub async fn upsert_observable(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: &NewObservable,
) -> Result<Upserted, DbError> {
    let row = sqlx::query!(
        r#"INSERT INTO analysis.observables AS o
               (root_id, type, value, time, tags, directives, exclude_modules, redirection_type,
                redirection_value)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (root_id, type, value_hash) DO UPDATE SET
               time = COALESCE(o.time, EXCLUDED.time),
               redirection_type = CASE
                   WHEN o.redirection_value IS NULL
                     OR (EXCLUDED.redirection_type, EXCLUDED.redirection_value)
                        < (o.redirection_type, o.redirection_value)
                   THEN EXCLUDED.redirection_type ELSE o.redirection_type END,
               redirection_value = CASE
                   WHEN o.redirection_value IS NULL
                     OR (EXCLUDED.redirection_type, EXCLUDED.redirection_value)
                        < (o.redirection_type, o.redirection_value)
                   THEN EXCLUDED.redirection_value ELSE o.redirection_value END,
               tags = analysis.merged(o.tags, EXCLUDED.tags),
               directives = analysis.merged(o.directives, EXCLUDED.directives),
               exclude_modules = analysis.merged(o.exclude_modules, EXCLUDED.exclude_modules)
           RETURNING id AS "id: ObservableId", (xmax = 0) AS "inserted!""#,
        root,
        observable.kind.as_str(),
        observable.value,
        observable.time,
        &observable.tags,
        &observable.directives,
        &observable.exclude_modules,
        observable.redirection.as_ref().map(|r| r.kind.as_str()),
        observable.redirection.as_ref().map(|r| r.value.as_str()),
    )
    .fetch_one(tx.conn())
    .await?;
    for relationship in &observable.relationships {
        let kind = serde_json::to_value(relationship.kind)
            .ok()
            .and_then(|kind| kind.as_str().map(str::to_owned))
            .ok_or_else(|| DbError::Decode(format!("{:?}", relationship.kind)))?;
        sqlx::query!(
            "INSERT INTO analysis.relationships
                 (root_id, observable_id, kind, target_type, target_value)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
            root,
            row.id as ObservableId,
            kind,
            relationship.target.kind.as_str(),
            relationship.target.value,
        )
        .execute(tx.conn())
        .await?;
    }
    Ok(Upserted {
        id: row.id,
        inserted: row.inserted,
    })
}

/// The root's observables, in the order they were added.
pub async fn observables<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
) -> Result<Vec<Observable>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT id AS "id: ObservableId", root_id, type AS kind, value, time, tags, directives,
                  exclude_modules
           FROM analysis.observables WHERE root_id = $1 ORDER BY id"#,
        root,
    )
    .fetch_all(executor)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(Observable {
                id: row.id,
                root: row.root_id,
                kind: row
                    .kind
                    .parse()
                    .map_err(|e| DbError::Decode(format!("observable {}: {e}", row.id.0)))?,
                value: row.value,
                time: row.time,
                tags: row.tags,
                directives: row.directives,
                exclude_modules: row.exclude_modules,
            })
        })
        .collect()
}

/// Stores a module's result for an observable, under its analysis type's name and version.
pub async fn insert_result(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    module: &str,
    result: &ResultEnvelope<Value>,
) -> Result<ResultId, DbError> {
    let id = sqlx::query_scalar!(
        r#"INSERT INTO analysis.results
               (root_id, observable_id, module, analysis_type, schema_version, details, summary,
                tags)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id AS "id: ResultId""#,
        root,
        observable as ObservableId,
        module,
        result.analysis_type(),
        i32::try_from(result.schema_version())
            .map_err(|_| DbError::Decode("schema version past i32".to_owned()))?,
        result.details,
        result.summary,
        &result.tags,
    )
    .fetch_one(tx.conn())
    .await?;
    Ok(id)
}

/// What a result adds to an observable already in the root: tags and directives it doesn't have
/// yet, and `yara_meta` tags on each path it has if it is a file. Detections are recorded apart,
/// with the result that raised them.
pub async fn add_to_observable(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    additions: &ObservableAdditions,
) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE analysis.observables
         SET tags = analysis.merged(tags, $3), directives = analysis.merged(directives, $4)
         WHERE root_id = $1 AND id = $2",
        root,
        observable as ObservableId,
        &additions.tags,
        &additions.directives,
    )
    .execute(tx.conn())
    .await?;
    let yara_meta: Vec<String> = additions
        .yara_meta
        .iter()
        .map(|tag| tag.as_str().to_owned())
        .collect();
    sqlx::query!(
        "UPDATE analysis.files SET yara_meta = analysis.merged(yara_meta, $3)
         WHERE root_id = $1 AND observable_id = $2",
        root,
        observable as ObservableId,
        &yara_meta,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The observable this one redirects to, as a result named it.
pub async fn redirection<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observable: ObservableId,
) -> Result<Option<ObservableRef>, DbError> {
    let row = sqlx::query!(
        "SELECT redirection_type, redirection_value FROM analysis.observables
         WHERE root_id = $1 AND id = $2",
        root,
        observable as ObservableId,
    )
    .fetch_optional(executor)
    .await?;
    let Some((Some(kind), Some(value))) = row.map(|r| (r.redirection_type, r.redirection_value))
    else {
        return Ok(None);
    };
    let kind = kind
        .parse()
        .map_err(|e| DbError::Decode(format!("observable {}: {e}", observable.0)))?;
    Ok(Some(ObservableRef::new(kind, value)))
}

/// The row of the observable with this type and value, if it is in the root.
pub async fn find_observable<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    target: &ObservableRef,
) -> Result<Option<ObservableId>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT id AS "id: ObservableId" FROM analysis.observables
           WHERE root_id = $1 AND type = $2 AND value_hash = analysis.value_hash($3)"#,
        root,
        target.kind.as_str(),
        target.value,
    )
    .fetch_optional(executor)
    .await?)
}

/// Records a detection on an observable, raised by `result`.
pub async fn add_detection(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    result: Option<ResultId>,
    detection: &Detection,
) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO analysis.detections
             (root_id, observable_id, result_id, description, details, queue, signature_uuid,
              signature_version, signature_family)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        root,
        observable as ObservableId,
        result as Option<ResultId>,
        detection.description,
        detection.details,
        detection.queue,
        detection.signature_uuid,
        detection.signature_version,
        detection.signature_family,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// A path a file has in a root, with its `yara_meta` tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub yara_meta: Vec<String>,
}

/// Records that the file observable is in the root at `path`, with these `yara_meta` tags. The
/// same path again merges its tags.
pub async fn add_file(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    path: &str,
    yara_meta: &[String],
) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO analysis.files AS f (root_id, observable_id, path, yara_meta)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (root_id, observable_id, path)
         DO UPDATE SET yara_meta = analysis.merged(f.yara_meta, EXCLUDED.yara_meta)",
        root,
        observable as ObservableId,
        path,
        yara_meta,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The first path a file observable was recorded under, which its tasks read it as.
pub async fn first_file<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observable: ObservableId,
) -> Result<Option<FileRecord>, DbError> {
    Ok(sqlx::query_as!(
        FileRecord,
        "SELECT path, yara_meta FROM analysis.files
         WHERE root_id = $1 AND observable_id = $2
         ORDER BY created_at, path LIMIT 1",
        root,
        observable as ObservableId,
    )
    .fetch_optional(executor)
    .await?)
}

/// Records that a result added an observable, and under what path if it's a file.
pub async fn add_result_addition(
    tx: &mut Tx<'_>,
    root: Uuid,
    result: ResultId,
    observable: ObservableId,
    path: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO analysis.result_additions (root_id, result_id, observable_id, path)
         VALUES ($1, $2, $3, $4)",
        root,
        result as ResultId,
        observable as ObservableId,
        path,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The body of the email that carried an observable: what `Module::READS_CARRYING_EMAIL` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailBodyFile {
    pub path: String,
    /// The file observable's value.
    pub sha256: String,
}

/// Whether an email in the root hasn't been parsed yet.
pub async fn emails_pending(pool: &PgPool, root: Uuid) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (
               SELECT 1 FROM queue.tasks
               WHERE root_id = $1 AND module = $2 AND state IN ('queued', 'delayed', 'running')
           ) AS "pending!""#,
        root,
        EmailAnalysis::MODULE,
    )
    .fetch_one(pool)
    .await?)
}

/// The email an observable came out of, as ace3's `search_down` finds its `EmailAnalysis`: up
/// through the results that added it, by any route, to the nearest email result that parsed a
/// message. A result lands after the one that added what it analyzed, so the highest id is the
/// nearest. None means no email carried it, and an inner None that one did but has no body.
pub async fn carrying_email(
    pool: &PgPool,
    root: Uuid,
    observable: ObservableId,
) -> Result<Option<Option<EmailBodyFile>>, DbError> {
    let email = sqlx::query_scalar!(
        r#"WITH RECURSIVE ancestors (observable_id) AS (
               SELECT $2::bigint
               UNION
               SELECT r.observable_id
               FROM ancestors
               JOIN analysis.result_additions a
                 ON a.root_id = $1 AND a.observable_id = ancestors.observable_id
               JOIN analysis.results r ON r.id = a.result_id
           )
           SELECT r.id AS "id: ResultId"
           FROM ancestors
           JOIN analysis.result_additions a
             ON a.root_id = $1 AND a.observable_id = ancestors.observable_id
           JOIN analysis.results r ON r.id = a.result_id
           WHERE r.analysis_type = $3 AND jsonb_typeof(r.details -> 'email') = 'object'
           ORDER BY r.id DESC
           LIMIT 1"#,
        root,
        observable as ObservableId,
        EmailAnalysis::NAME,
    )
    .fetch_optional(pool)
    .await?;
    let Some(email) = email else {
        return Ok(None);
    };
    let files = sqlx::query!(
        r#"SELECT a.path AS "path!", o.value
           FROM analysis.result_additions a
           JOIN analysis.observables o ON o.root_id = a.root_id AND o.id = a.observable_id
           WHERE a.result_id = $1 AND a.path IS NOT NULL
           ORDER BY a.id"#,
        email as ResultId,
    )
    .fetch_all(pool)
    .await?;
    let names: Vec<&str> = files
        .iter()
        .map(|file| file.path.rsplit('/').next().unwrap_or_default())
        .collect();
    Ok(Some(EmailAnalysis::body_of(&names).map(|index| {
        EmailBodyFile {
            path: files[index].path.clone(),
            sha256: files[index].value.clone(),
        }
    })))
}
