//! The alert tree in Postgres: roots, their observables and the results about them.
//!
//! An observable is unique on (root, type, value), so adding one that is already there merges
//! its tags, directives, excluded modules and relationships into the existing row. A result is
//! unique on (root, observable, module).

use ace_results::types::email::EmailAnalysis;
use ace_results::types::yara::YaraScanResults;
use ace_results::{
    AnalysisType, Detection, NewObservable, ObservableAdditions, ObservableKind, ObservableRef,
    Relationship, ResultEnvelope,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::db::{DbError, Tx};
use ace_sdk::wire::RelatedTags;

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
/// lacks are added. A display type replaces the stored one, as ace3's setter does on the one
/// observable it keeps per type and value, so the last result to land with one names it. Of two redirections the lowest is kept, so a tree doesn't depend on which task
/// ended first: a macro in a `.docm` is in the `.docm` and in the `vbaProject.bin` taken out of it,
/// each redirecting to where it was found.
pub async fn upsert_observable(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: &NewObservable,
) -> Result<Upserted, DbError> {
    upsert_observable_at(tx, root, observable, 0).await
}

/// `upsert_observable` for an observable at `depth`, one more than the observable whose result
/// added it, or 0 for one a submission or an analyst added. Of two depths the least is kept.
pub async fn upsert_observable_at(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: &NewObservable,
    depth: i32,
) -> Result<Upserted, DbError> {
    let row = sqlx::query!(
        r#"INSERT INTO analysis.observables AS o
               (root_id, type, value, time, tags, directives, exclude_modules, redirection_type,
                redirection_value, display_type, depth)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (root_id, type, value_hash) DO UPDATE SET
               time = COALESCE(o.time, EXCLUDED.time),
               depth = LEAST(o.depth, EXCLUDED.depth),
               display_type = COALESCE(EXCLUDED.display_type, o.display_type),
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
        observable.display_type,
        depth,
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

/// The observable's relationships, as results gave them, such as a command line `executed_on` a
/// host. A task carries them, as ace3's observable does.
pub async fn relationships<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observable: ObservableId,
) -> Result<Vec<Relationship>, DbError> {
    let rows = sqlx::query!(
        "SELECT kind, target_type, target_value FROM analysis.relationships
         WHERE root_id = $1 AND observable_id = $2
         ORDER BY kind, target_type, target_value",
        root,
        observable as ObservableId,
    )
    .fetch_all(executor)
    .await?;
    rows.into_iter()
        .map(|row| {
            let kind = serde_json::from_value(Value::String(row.kind.clone())).map_err(|e| {
                DbError::Decode(format!("observable {}: {}: {e}", observable.0, row.kind))
            })?;
            let target = row
                .target_type
                .parse()
                .map_err(|e| DbError::Decode(format!("observable {}: {e}", observable.0)))?;
            Ok(Relationship::new(
                kind,
                ObservableRef::new(target, row.target_value),
            ))
        })
        .collect()
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
    add_file_at(tx, root, observable, path, yara_meta, 0).await
}

/// `add_file` for a path a result wrote, at `depth`, the depth of the file it adds
/// (`upsert_observable_at`). The same path at two depths keeps the least.
pub async fn add_file_at(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    path: &str,
    yara_meta: &[String],
    depth: i32,
) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO analysis.files AS f (root_id, observable_id, path, yara_meta, depth)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (root_id, observable_id, path)
         DO UPDATE SET yara_meta = analysis.merged(f.yara_meta, EXCLUDED.yara_meta),
                       depth = LEAST(f.depth, EXCLUDED.depth)",
        root,
        observable as ObservableId,
        path,
        yara_meta,
        depth,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The observable's depth: 0 for one a submission added, else one more than the shallowest
/// observable whose result added it (`upsert_observable_at`).
pub async fn depth<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observable: ObservableId,
) -> Result<i32, DbError> {
    sqlx::query_scalar!(
        "SELECT depth FROM analysis.observables WHERE root_id = $1 AND id = $2",
        root,
        observable as ObservableId,
    )
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| DbError::Decode(format!("no observable {} in root {root}", observable.0)))
}

/// The path a file observable is analyzed under (PLAN.md decision 15): the one its first task
/// chose (`choose_analysis_file`), or, before that, the one it would choose now. None when the
/// file has no path in the root.
pub async fn analysis_file<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observable: ObservableId,
) -> Result<Option<FileRecord>, DbError> {
    Ok(sqlx::query_as!(
        FileRecord,
        r#"SELECT path, yara_meta FROM analysis.files
           WHERE root_id = $1 AND observable_id = $2
           ORDER BY analyzed DESC, depth, path COLLATE "C" LIMIT 1"#,
        root,
        observable as ObservableId,
    )
    .fetch_optional(executor)
    .await?)
}

/// Settles the path a file observable is analyzed under, if no task of it has yet, and returns
/// it. Of its paths it takes the shallowest, by the depth of the results that wrote them, and of
/// those the first in byte order. A path written from deeper in the tree, such as a file that
/// holds itself, is never chosen over one nearer the root. Every task of the file reads it under
/// this path, whenever it runs, so a path that arrives later changes nothing.
///
/// The caller holds the file's first task until nothing nearer the root that could still add a
/// path is pending (`pending_above`), which is what makes the choice not depend on which result
/// landed first.
pub async fn choose_analysis_file(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
) -> Result<Option<FileRecord>, DbError> {
    // two first tasks of one file leased at once take turns here
    sqlx::query!(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND id = $2 FOR UPDATE",
        root,
        observable as ObservableId,
    )
    .fetch_optional(tx.conn())
    .await?;
    sqlx::query!(
        r#"UPDATE analysis.files SET analyzed = true
           WHERE root_id = $1 AND observable_id = $2
             AND NOT EXISTS (SELECT FROM analysis.files
                             WHERE root_id = $1 AND observable_id = $2 AND analyzed)
             AND path = (SELECT path FROM analysis.files
                         WHERE root_id = $1 AND observable_id = $2
                         ORDER BY depth, path COLLATE "C" LIMIT 1)"#,
        root,
        observable as ObservableId,
    )
    .execute(tx.conn())
    .await?;
    analysis_file(tx.conn(), root, observable).await
}

/// Whether a file observable's analysis path is settled (`choose_analysis_file`), and how long ago,
/// by the database's clock, its first path was recorded.
pub async fn analysis_file_state<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observable: ObservableId,
) -> Result<(bool, std::time::Duration), DbError> {
    let row = sqlx::query!(
        r#"SELECT COALESCE(bool_or(analyzed), false) AS "chosen!",
                  COALESCE(EXTRACT(EPOCH FROM now() - min(created_at)), 0)::float8 AS "waited!"
           FROM analysis.files WHERE root_id = $1 AND observable_id = $2"#,
        root,
        observable as ObservableId,
    )
    .fetch_one(executor)
    .await?;
    let waited = std::time::Duration::try_from_secs_f64(row.waited.max(0.0)).unwrap_or_default();
    Ok((row.chosen, waited))
}

/// Whether the root has a task that hasn't finished on an observable shallower than `depth`, of a
/// module not in `except`: one whose result could still add a path to a file at `depth`.
pub async fn pending_above(
    pool: &PgPool,
    root: Uuid,
    depth: i32,
    except: &[String],
) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (
               SELECT 1 FROM queue.tasks t
               JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
               WHERE t.root_id = $1
                 AND t.state IN ('queued', 'delayed', 'running')
                 AND o.depth < $2
                 AND t.module <> ALL($3)
           ) AS "pending!""#,
        root,
        depth,
        except,
    )
    .fetch_one(pool)
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

/// What holds back a task that runs last (`held_back`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldBack {
    /// A module that doesn't run last has a task in the root that hasn't finished.
    ByOthers,
    /// A module that runs last has one on a file below the task's observable.
    ByLastBelow,
}

impl HeldBack {
    pub fn as_str(self) -> &'static str {
        match self {
            HeldBack::ByOthers => "others",
            HeldBack::ByLastBelow => "last_below",
        }
    }
}

/// Whether a task that runs last, on `observable`, must wait, and for what: a module not in `last` has
/// a task in the root that hasn't finished, or one in `last` has one on a file below `observable`, what
/// its results added and theirs in turn. What's below is what a module that runs last reads, and one
/// that runs last on a file can add to it, as xlmdeobfuscator adds its output under an email's
/// attachment, where the email's lure_url_analyzer finds its URLs; extracted_ole_analyzer and
/// pcap_tls_decryption add files too. One on another type isn't waited for: email_thread_analyzer, on a
/// message_id below the email, adds nothing and waits itself for the email logger above it, so waiting
/// for it would never end. Nor are those on the same observable, above it, elsewhere in the root, or
/// both above and below it in a cycle, so no two wait on each other while a module that runs last on a
/// file waits for none above it. The walk below is read only once nothing else is left.
pub async fn held_back(
    pool: &PgPool,
    root: Uuid,
    observable: ObservableId,
    last: &[String],
) -> Result<Option<HeldBack>, DbError> {
    if others_pending(pool, root, last).await? {
        return Ok(Some(HeldBack::ByOthers));
    }
    let below = sqlx::query_scalar!(
        r#"WITH RECURSIVE below (observable_id) AS (
               SELECT a.observable_id
               FROM analysis.results r
               JOIN analysis.result_additions a ON a.result_id = r.id
               WHERE r.root_id = $1 AND r.observable_id = $2
               UNION
               SELECT a.observable_id
               FROM below
               JOIN analysis.results r ON r.root_id = $1 AND r.observable_id = below.observable_id
               JOIN analysis.result_additions a ON a.result_id = r.id
           ), above (observable_id) AS (
               SELECT r.observable_id
               FROM analysis.result_additions a
               JOIN analysis.results r ON r.id = a.result_id
               WHERE a.root_id = $1 AND a.observable_id = $2
               UNION
               SELECT r.observable_id
               FROM above
               JOIN analysis.result_additions a
                 ON a.root_id = $1 AND a.observable_id = above.observable_id
               JOIN analysis.results r ON r.id = a.result_id
           )
           SELECT EXISTS (
               SELECT 1 FROM queue.tasks t
               JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
               WHERE t.root_id = $1
                 AND t.state IN ('queued', 'delayed', 'running')
                 AND t.module = ANY($3)
                 AND o.type = $4
                 AND t.observable_id <> $2
                 AND t.observable_id IN (SELECT observable_id FROM below)
                 AND t.observable_id NOT IN (SELECT observable_id FROM above)
           ) AS "pending!""#,
        root,
        observable as ObservableId,
        last,
        ObservableKind::File.as_str(),
    )
    .fetch_one(pool)
    .await?;
    Ok(below.then_some(HeldBack::ByLastBelow))
}

/// Whether a module not in `except` has a task in the root that hasn't finished.
pub async fn others_pending(pool: &PgPool, root: Uuid, except: &[String]) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (
               SELECT 1 FROM queue.tasks
               WHERE root_id = $1
                 AND state IN ('queued', 'delayed', 'running')
                 AND module <> ALL($2)
           ) AS "pending!""#,
        root,
        except,
    )
    .fetch_one(pool)
    .await?)
}

/// The names of the YARA rules that matched an observable or anything added below it, as ace3's
/// `recurse_tree` finds them, sorted. A file that contains its own ancestor ends the walk.
pub async fn yara_rules_below(
    pool: &PgPool,
    root: Uuid,
    observable: ObservableId,
) -> Result<Vec<String>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"WITH RECURSIVE below (observable_id) AS (
               SELECT $2::bigint
               UNION
               SELECT a.observable_id
               FROM below
               JOIN analysis.results r ON r.root_id = $1 AND r.observable_id = below.observable_id
               JOIN analysis.result_additions a ON a.result_id = r.id
           )
           SELECT DISTINCT match ->> 'rule' AS "rule!"
           FROM below
           JOIN analysis.results r ON r.root_id = $1 AND r.observable_id = below.observable_id
           CROSS JOIN LATERAL jsonb_array_elements(r.details -> 'scan_results') AS match
           WHERE r.analysis_type = $3 AND match ->> 'rule' IS NOT NULL
           ORDER BY 1"#,
        root,
        observable as ObservableId,
        YaraScanResults::NAME,
    )
    .fetch_all(pool)
    .await?)
}

/// The details of the observable's results from `modules`, by module, as a module that depends on
/// them reads them (`Module::DEPENDS_ON`). A module has one result per observable.
pub async fn results_of(
    pool: &PgPool,
    root: Uuid,
    observable: ObservableId,
    modules: &[&str],
) -> Result<Vec<(String, Value)>, DbError> {
    let modules: Vec<String> = modules.iter().map(|m| (*m).to_owned()).collect();
    let rows = sqlx::query!(
        r#"SELECT module, details
           FROM analysis.results
           WHERE root_id = $1 AND observable_id = $2 AND module = ANY($3)
           ORDER BY module"#,
        root,
        observable as ObservableId,
        &modules,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.module, r.details)).collect())
}

/// The observables of `kinds` added below an observable, by any route, as ace3's `recurse_tree`
/// finds them, in the order they were added. A file that contains its own ancestor ends the walk.
/// The modules whose results added `observable`, by name, in the order of their first such result:
/// what ace3's `iterate_all_references` finds holding it (`Module::READS_ADDED_BY`).
pub async fn added_by(
    pool: &PgPool,
    root: Uuid,
    observable: ObservableId,
) -> Result<Vec<String>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT r.module AS "module!"
           FROM analysis.result_additions a
           JOIN analysis.results r ON r.id = a.result_id
           WHERE a.root_id = $1 AND a.observable_id = $2
           GROUP BY r.module
           ORDER BY min(a.id)"#,
        root,
        observable as ObservableId,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|row| row.module).collect())
}

/// The tags of each observable `observable` has a relationship to, in the order of its
/// relationships (`Module::READS_RELATED_TAGS`). A target the root doesn't hold has none.
pub async fn related_tags(
    pool: &PgPool,
    root: Uuid,
    observable: ObservableId,
) -> Result<Vec<RelatedTags>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT DISTINCT rel.target_type, rel.target_value,
                  COALESCE(o.tags, '{}') AS "tags!"
           FROM analysis.relationships rel
           LEFT JOIN analysis.observables o
             ON o.root_id = rel.root_id AND o.type = rel.target_type
            AND o.value_hash = rel.target_value_hash
           WHERE rel.root_id = $1 AND rel.observable_id = $2
           ORDER BY rel.target_type, rel.target_value"#,
        root,
        observable as ObservableId,
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let kind = row
                .target_type
                .parse()
                .map_err(|e| DbError::Decode(format!("observable {}: {e}", observable.0)))?;
            Ok(RelatedTags {
                observable: ObservableRef::new(kind, row.target_value),
                tags: row.tags,
            })
        })
        .collect()
}

pub async fn observables_below(
    pool: &PgPool,
    root: Uuid,
    observable: ObservableId,
    kinds: &[ObservableKind],
) -> Result<Vec<ObservableRef>, DbError> {
    let kinds: Vec<String> = kinds.iter().map(|k| k.as_str().to_owned()).collect();
    let rows = sqlx::query!(
        r#"WITH RECURSIVE below (observable_id) AS (
               SELECT a.observable_id
               FROM analysis.results r
               JOIN analysis.result_additions a ON a.result_id = r.id
               WHERE r.root_id = $1 AND r.observable_id = $2
               UNION
               SELECT a.observable_id
               FROM below
               JOIN analysis.results r ON r.root_id = $1 AND r.observable_id = below.observable_id
               JOIN analysis.result_additions a ON a.result_id = r.id
           )
           SELECT o.type AS kind, o.value
           FROM below JOIN analysis.observables o ON o.root_id = $1 AND o.id = below.observable_id
           WHERE o.type = ANY($3)
           ORDER BY o.id"#,
        root,
        observable as ObservableId,
        &kinds,
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let kind = row
                .kind
                .parse()
                .map_err(|e| DbError::Decode(format!("observable {}: {e}", row.value)))?;
            Ok(ObservableRef::new(kind, row.value))
        })
        .collect()
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

/// Whether any of the root's observables is whitelisted: it has ace3's `whitelisted` tag or directive
/// (`eligibility::is_whitelisted`).
pub async fn has_whitelisted(executor: impl PgExecutor<'_>, root: Uuid) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT FROM analysis.observables
                          WHERE root_id = $1
                            AND ('whitelisted' = ANY(tags) OR 'whitelisted' = ANY(directives)))
           AS "whitelisted!""#,
        root,
    )
    .fetch_one(executor)
    .await?)
}

/// The root's tree as a module that walks it reads it (`Module::READS_TREE`, `ace_sdk::tree`), as it
/// is now, with `this` the task's observable. Of the files the module reads (`files`), each one's
/// sha256 and index comes back beside it, for the caller to add a download. A root past
/// `MAX_TREE_OBSERVABLES` or `MAX_TREE_RESULTS` is cut in the order its rows were added, and says
/// so; a cut observable's results and additions are left out too. Each read is a separate
/// statement, so a result landing between them can leave an addition naming an observable the
/// view lacks; that addition is dropped.
pub async fn tree_view(
    pool: &PgPool,
    root: Uuid,
    this: ObservableId,
    files: Option<ace_sdk::tree::TreeFiles>,
    details_of: &[&str],
) -> Result<(ace_sdk::tree::TreeView, Vec<(usize, String)>), DbError> {
    use ace_sdk::tree::{
        MAX_TREE_OBSERVABLES, MAX_TREE_RESULTS, TreeAddition, TreeObservable, TreePath,
        TreeRelationship, TreeResult, TreeView,
    };
    use std::collections::HashMap;

    let head = sqlx::query!(
        r#"SELECT origin ->> 'alert_type' AS alert_type, analysis_mode
           FROM analysis.roots WHERE id = $1"#,
        root,
    )
    .fetch_optional(pool)
    .await?;
    let (alert_type, analysis_mode) = match head {
        Some(row) => (row.alert_type, Some(row.analysis_mode)),
        None => (None, None),
    };
    let whitelisted = has_whitelisted(pool, root).await?;

    let limit = MAX_TREE_OBSERVABLES as i64 + 1;
    let rows = sqlx::query!(
        r#"SELECT o.id AS "id: ObservableId", o.type, o.value, o.tags, o.directives,
                  (SELECT count(*) FROM analysis.detections d
                   WHERE d.root_id = o.root_id AND d.observable_id = o.id) AS "detections!",
                  (SELECT s.size FROM store.objects s
                   WHERE o.type = 'file' AND s.pool = $3 AND s.sha256 = o.value) AS size
           FROM analysis.observables o
           WHERE o.root_id = $1
           ORDER BY o.id
           LIMIT $2"#,
        root,
        limit,
        crate::bucket::ALERT_FILES,
    )
    .fetch_all(pool)
    .await?;
    let mut truncated = rows.len() > MAX_TREE_OBSERVABLES;
    let mut index: HashMap<ObservableId, usize> = HashMap::new();
    let mut observables = Vec::new();
    for row in rows.into_iter().take(MAX_TREE_OBSERVABLES) {
        let kind: ObservableKind = row
            .r#type
            .parse()
            .map_err(|e| DbError::Decode(format!("observable {}: {e}", row.id.0)))?;
        index.insert(row.id, observables.len());
        observables.push(TreeObservable {
            kind,
            value: row.value,
            tags: row.tags,
            directives: row.directives,
            detections: u32::try_from(row.detections).unwrap_or(u32::MAX),
            paths: Vec::new(),
            size: row.size.and_then(|s| u64::try_from(s).ok()),
            pending: Vec::new(),
            download: None,
            relationships: Vec::new(),
        });
    }
    let Some(&this_index) = index.get(&this) else {
        return Err(DbError::Decode(format!(
            "observable {} isn't among its root's first {MAX_TREE_OBSERVABLES}",
            this.0
        )));
    };

    let paths = sqlx::query!(
        r#"SELECT observable_id AS "observable_id: ObservableId", path, yara_meta
           FROM analysis.files WHERE root_id = $1
           ORDER BY created_at, path COLLATE "C""#,
        root,
    )
    .fetch_all(pool)
    .await?;
    for row in paths {
        if let Some(&i) = index.get(&row.observable_id) {
            observables[i].paths.push(TreePath {
                path: row.path,
                yara_meta: row.yara_meta,
            });
        }
    }

    let pending = sqlx::query!(
        r#"SELECT observable_id AS "observable_id: ObservableId", module
           FROM queue.tasks
           WHERE root_id = $1 AND state IN ('queued', 'delayed', 'running')
           ORDER BY id"#,
        root,
    )
    .fetch_all(pool)
    .await?;
    for row in pending {
        if let Some(&i) = index.get(&row.observable_id)
            && !observables[i].pending.contains(&row.module)
        {
            observables[i].pending.push(row.module);
        }
    }

    let relationships = sqlx::query!(
        r#"SELECT r.observable_id AS "observable_id: ObservableId", r.kind,
                  t.id AS "target: ObservableId"
           FROM analysis.relationships r
           JOIN analysis.observables t
             ON t.root_id = r.root_id AND t.type = r.target_type
                AND t.value_hash = r.target_value_hash
           WHERE r.root_id = $1
           ORDER BY r.observable_id, r.kind, r.target_type, r.target_value"#,
        root,
    )
    .fetch_all(pool)
    .await?;
    for row in relationships {
        let (Some(&from), Some(&target)) = (index.get(&row.observable_id), index.get(&row.target))
        else {
            continue;
        };
        let Ok(kind) = serde_json::from_value(Value::String(row.kind.clone())) else {
            continue;
        };
        observables[from]
            .relationships
            .push(TreeRelationship { kind, target });
    }

    let limit = MAX_TREE_RESULTS as i64 + 1;
    let details_of: Vec<String> = details_of.iter().map(|m| (*m).to_owned()).collect();
    let rows = sqlx::query!(
        r#"SELECT id AS "id: ResultId", observable_id AS "observable_id: ObservableId",
                  module, analysis_type, tags,
                  CASE WHEN module = ANY($3) THEN details END AS details
           FROM analysis.results WHERE root_id = $1
           ORDER BY id
           LIMIT $2"#,
        root,
        limit,
        &details_of,
    )
    .fetch_all(pool)
    .await?;
    truncated |= rows.len() > MAX_TREE_RESULTS;
    let mut result_index: HashMap<ResultId, usize> = HashMap::new();
    let mut results = Vec::new();
    for row in rows.into_iter().take(MAX_TREE_RESULTS) {
        let Some(&observable) = index.get(&row.observable_id) else {
            continue;
        };
        result_index.insert(row.id, results.len());
        results.push(TreeResult {
            observable,
            module: row.module,
            analysis_type: row.analysis_type,
            tags: row.tags,
            added: Vec::new(),
            details: row.details,
        });
    }
    let additions = sqlx::query!(
        r#"SELECT result_id AS "result_id: ResultId", observable_id AS "observable_id: ObservableId",
                  path
           FROM analysis.result_additions WHERE root_id = $1
           ORDER BY id"#,
        root,
    )
    .fetch_all(pool)
    .await?;
    let mut wanted = Vec::new();
    for row in additions {
        let (Some(&result), Some(&observable)) = (
            result_index.get(&row.result_id),
            index.get(&row.observable_id),
        ) else {
            continue;
        };
        if let (Some(files), Some(path)) = (&files, &row.path) {
            let o = &observables[observable];
            if o.kind == ObservableKind::File
                && files.wants(path, o.size.unwrap_or(u64::MAX), &o.tags)
                && !wanted.iter().any(|(i, _)| *i == observable)
            {
                wanted.push((observable, o.value.clone()));
            }
        }
        results[result].added.push(TreeAddition {
            observable,
            path: row.path,
        });
    }
    Ok((
        TreeView {
            alert_type,
            analysis_mode,
            whitelisted,
            this: this_index,
            observables,
            results,
            truncated,
        },
        wanted,
    ))
}

/// What a result changes about its root (`ResultEnvelope::root`): its description, and keys merged
/// into its details, as Python's `dict.update` merges them. A root's details are the `details` its
/// submitter gave in its origin; one with none gets them.
pub async fn change_root(
    tx: &mut Tx<'_>,
    root: Uuid,
    changes: &ace_results::RootChanges,
) -> Result<(), DbError> {
    let details = changes.details.clone().map(Value::Object);
    sqlx::query!(
        r#"UPDATE analysis.roots
           SET description = COALESCE($2, description),
               origin = CASE WHEN $3::jsonb IS NULL THEN origin
                        ELSE jsonb_set(
                            CASE WHEN jsonb_typeof(origin) = 'object' THEN origin ELSE '{}'::jsonb END,
                            '{details}',
                            CASE WHEN jsonb_typeof(origin -> 'details') = 'object'
                                 THEN origin -> 'details' ELSE '{}'::jsonb END || $3::jsonb)
                        END
           WHERE id = $1"#,
        root,
        changes.description.as_deref(),
        details,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}
