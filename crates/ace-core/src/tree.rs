//! The alert tree in Postgres: roots, their observables and the results about them.
//!
//! An observable is unique on (root, type, value), so adding one that is already there merges
//! its tags, directives and excluded modules into the existing row. A result is unique on
//! (root, observable, module).

use ace_results::{Detection, NewObservable, ObservableKind, ResultEnvelope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
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
/// stored time is kept if it has one, and tags, directives and excluded modules it lacks are
/// appended.
pub async fn upsert_observable(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: &NewObservable,
) -> Result<Upserted, DbError> {
    let row = sqlx::query!(
        r#"INSERT INTO analysis.observables AS o
               (root_id, type, value, time, tags, directives, exclude_modules)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (root_id, type, value_hash) DO UPDATE SET
               time = COALESCE(o.time, EXCLUDED.time),
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
    )
    .fetch_one(tx.conn())
    .await?;
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

/// Appends tags and directives an observable doesn't have yet, as a result's additions to the
/// observable it analyzed.
pub async fn add_to_observable(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    tags: &[String],
    directives: &[String],
) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE analysis.observables
         SET tags = analysis.merged(tags, $3), directives = analysis.merged(directives, $4)
         WHERE root_id = $1 AND id = $2",
        root,
        observable as ObservableId,
        tags,
        directives,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
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
