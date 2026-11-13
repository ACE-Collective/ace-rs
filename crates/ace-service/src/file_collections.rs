//! File collections (PLAN.md 7.9): ace3's `aceapi_v2/file_collection` service and `saq/file_collection`'s
//! helpers, for the `file_collection` router (5.6) and the GUI's file collections area (5.11).
//!
//! A file collection is an action of `ace_core::actions`, which a network pool hosting its collector leases
//! and tries, backing off, until it completes or runs out of tries or time. Here are its list, its tries and
//! the writes on it under `file_collection:write`, each with its audit row: stopping, retrying and deleting
//! one. ace3's router has no way to ask for a collection: its integrations' modules and its EndpointVendor API
//! do, and here a module's request is `ace_core::actions::request_collection`, which joins a pending
//! collection of the same file so that each alert that asks holds the file (#1101).
//!
//! `prune_file_collections` is ace3's `ace file-collection prune`, which the scheduler runs daily as
//! `file_collection_prune` under `file_collection:prune`: it lets go of each collection's own hold on its
//! file once the collection completed `ace_core::actions::COLLECTION_RETENTION` ago, and the alerts that
//! asked keep theirs. ace3 deletes the directory of a collection no alert asked for; here the bucket's GC
//! deletes the bytes once nothing holds them.

use ace_core::actions as core_actions;
use ace_sdk::actions::ActionKind;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::alerts::{SET_LIST_TIMEOUT, page_limit, timed_out};
use crate::filters::{FilterEntry, FilterScreen, Resolved, split};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{FILE_COLLECTION_PRUNE, FILE_COLLECTION_READ, FILE_COLLECTION_WRITE};
use crate::remediation::{
    ActionAttempt, ActionQuery, ActionSummary, MAX_ACTIONS_PAGE, action_state, history_in, ids,
    no_action, summary_in,
};
use crate::{Actor, Service, ServiceError};

/// One file collection, as its list shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct FileCollection {
    pub id: i64,
    pub collector: String,
    pub display_name: Option<String>,
    pub observable_type: String,
    pub observable_value: String,
    /// `NEW`, `IN_PROGRESS` (waiting to be tried again) or `COMPLETED`.
    pub status: String,
    pub result: Option<String>,
    pub result_message: Option<String>,
    pub attempts: i32,
    pub max_attempts: Option<i32>,
    /// The alerts it belongs to, in the order they asked.
    pub alerts: Vec<Uuid>,
    /// Who asked when no alert did, by their username now or as they were named.
    pub requested_by: Option<String>,
    /// The file, once collected: its sha256, size and name.
    pub file: Option<(String, i64, String)>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// One page of collections, newest first, the filters' total, and the cursor for the next.
#[derive(Debug, Clone, PartialEq)]
pub struct FileCollectionPage {
    pub collections: Vec<FileCollection>,
    pub total: i64,
    pub next: Option<i64>,
}

/// What a prune let go of.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CollectionsPruned {
    pub released: u64,
    /// Transactions that let files go, each with its audit row.
    pub batches: u64,
}

#[derive(Serialize)]
struct Released {
    retention_days: u64,
    collections: Vec<core_actions::PrunedCollection>,
}

impl Recorded for Released {}

/// The file collections screen's parameters, in the order its query takes them.
type Params = (
    [Option<Vec<i64>>; 2],
    [Option<Vec<String>>; 10],
    [Option<Vec<Uuid>>; 2],
    [Option<Vec<DateTime<Utc>>>; 4],
);

fn uuids(values: Option<Vec<String>>) -> Option<Vec<Uuid>> {
    values.map(|values| values.iter().filter_map(|v| v.parse().ok()).collect())
}

fn params(query: &ActionQuery) -> Result<Params, ServiceError> {
    let f = Resolved::new(
        FilterScreen::FileCollections,
        &query.filters,
        Utc::now(),
        query.tz,
    )?;
    let ((c1, c2), (c3, c4)) = (
        split(f.windows("created", false)?),
        split(f.windows("created", true)?),
    );
    Ok((
        [ids(f.names("id", false)), ids(f.names("id", true))],
        [
            f.patterns("collector", false, false),
            f.patterns("collector", true, false),
            f.patterns("type", false, false),
            f.patterns("type", true, false),
            f.patterns("value", false, false),
            f.patterns("value", true, false),
            f.names("status", false),
            f.names("status", true),
            f.names("result", false),
            f.names("result", true),
        ],
        [
            uuids(f.names("alert", false)),
            uuids(f.names("alert", true)),
        ],
        [c1, c2, c3, c4],
    ))
}

impl Service {
    /// A page of file collections, newest first, of up to `limit` (100 when None, at most
    /// `MAX_ACTIONS_PAGE`), after the collection `after` names, with the filters' total.
    pub async fn file_collections(
        &self,
        actor: &Actor,
        query: &ActionQuery,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<FileCollectionPage, ServiceError> {
        let limit = page_limit(limit, MAX_ACTIONS_PAGE)?;
        let params = &params(query)?;
        let (mut collections, total) = self
            .gate
            .read(actor, "file_collections", &FILE_COLLECTION_READ, &|tx| {
                Box::pin(async move {
                    let ([i1, i2], t, [a1, a2], [c1, c2, c3, c4]) = params;
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let rows = sqlx::query!(
                        r#"WITH matched AS (
                             SELECT a.id, a.handler, a.observable_type, a.observable_value, a.status,
                                    a.result, a.result_message, a.attempts, a.max_attempts,
                                    a.file_sha256, a.file_size, a.file_name, a.created_at, a.updated_at,
                                    coalesce(u.username::text, a.requested_by ->> 'name') AS requested_by,
                                    array(SELECT r.root_id FROM queue.action_roots r
                                          WHERE r.action_id = a.id
                                          ORDER BY r.created_at, r.root_id) AS alerts
                             FROM queue.actions a LEFT JOIN service.users u ON u.id = a.user_id
                             WHERE a.kind = 'file_collection'
                               AND ($3::bigint[] IS NULL OR a.id = ANY ($3))
                               AND ($4::bigint[] IS NULL OR NOT a.id = ANY ($4))
                               AND ($5::text[] IS NULL OR a.handler ILIKE ANY ($5))
                               AND ($6::text[] IS NULL OR NOT a.handler ILIKE ANY ($6))
                               AND ($7::text[] IS NULL OR a.observable_type ILIKE ANY ($7))
                               AND ($8::text[] IS NULL OR NOT a.observable_type ILIKE ANY ($8))
                               AND ($9::text[] IS NULL OR a.observable_value ILIKE ANY ($9))
                               AND ($10::text[] IS NULL OR NOT a.observable_value ILIKE ANY ($10))
                               AND ($11::text[] IS NULL OR a.status = ANY ($11))
                               AND ($12::text[] IS NULL OR NOT a.status = ANY ($12))
                               AND ($13::text[] IS NULL OR a.result = ANY ($13))
                               AND ($14::text[] IS NULL OR NOT coalesce(a.result = ANY ($14), false))
                               AND ($15::uuid[] IS NULL OR EXISTS (
                                     SELECT FROM queue.action_roots r
                                     WHERE r.action_id = a.id AND r.root_id = ANY ($15)))
                               AND ($16::uuid[] IS NULL OR NOT EXISTS (
                                     SELECT FROM queue.action_roots r
                                     WHERE r.action_id = a.id AND r.root_id = ANY ($16)))
                               AND ($17::timestamptz[] IS NULL OR EXISTS (
                                     SELECT FROM unnest($17::timestamptz[], $18::timestamptz[]) w(s, e)
                                     WHERE a.created_at BETWEEN w.s AND w.e))
                               AND ($19::timestamptz[] IS NULL OR NOT EXISTS (
                                     SELECT FROM unnest($19::timestamptz[], $20::timestamptz[]) w(s, e)
                                     WHERE a.created_at BETWEEN w.s AND w.e))
                           )
                           SELECT m.*, (SELECT count(*) FROM matched) AS "total!"
                           FROM matched m
                           WHERE $2::bigint IS NULL OR m.id < $2
                           ORDER BY m.id DESC
                           LIMIT $1"#,
                        limit + 1,
                        after,
                        i1.as_deref(),
                        i2.as_deref(),
                        t[0].as_deref(),
                        t[1].as_deref(),
                        t[2].as_deref(),
                        t[3].as_deref(),
                        t[4].as_deref(),
                        t[5].as_deref(),
                        t[6].as_deref(),
                        t[7].as_deref(),
                        t[8].as_deref(),
                        t[9].as_deref(),
                        a1.as_deref(),
                        a2.as_deref(),
                        c1.as_deref(),
                        c2.as_deref(),
                        c3.as_deref(),
                        c4.as_deref(),
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?;
                    let total = rows.first().map_or(0, |row| row.total);
                    let collections: Vec<FileCollection> = rows
                        .into_iter()
                        .map(|row| {
                            let file = match (row.file_sha256, row.file_size, row.file_name) {
                                (Some(sha256), Some(size), Some(name)) => Some((sha256, size, name)),
                                _ => None,
                            };
                            FileCollection {
                                id: row.id,
                                display_name: None,
                                collector: row.handler,
                                observable_type: row.observable_type,
                                observable_value: row.observable_value,
                                status: row.status,
                                result: row.result,
                                result_message: row.result_message,
                                attempts: row.attempts,
                                max_attempts: row.max_attempts,
                                alerts: row.alerts.unwrap_or_default(),
                                requested_by: row.requested_by,
                                file,
                                created_at: row.created_at,
                                updated_at: row.updated_at,
                            }
                        })
                        .collect();
                    Ok((collections, total))
                })
            })
            .await?;
        for collection in &mut collections {
            collection.display_name = self
                .actions
                .get(ActionKind::FileCollection, &collection.collector)
                .map(|spec| spec.display_name.to_owned());
        }
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let more = collections.len() > limit;
        collections.truncate(limit);
        let next = if more {
            collections.last().map(|c| c.id)
        } else {
            None
        };
        Ok(FileCollectionPage {
            collections,
            total,
            next,
        })
    }

    /// One file collection.
    pub async fn file_collection(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<FileCollection, ServiceError> {
        let query = ActionQuery {
            filters: vec![FilterEntry::text("ID", false, &[&id.to_string()])],
            ..ActionQuery::default()
        };
        self.file_collections(actor, &query, Some(1), None)
            .await?
            .collections
            .pop()
            .ok_or_else(|| no_action(ActionKind::FileCollection, id))
    }

    /// A collection's tries, newest first, up to `limit`.
    pub async fn file_collection_history(
        &self,
        actor: &Actor,
        id: i64,
        limit: u32,
    ) -> Result<Vec<ActionAttempt>, ServiceError> {
        self.gate
            .read(
                actor,
                "file_collection_history",
                &FILE_COLLECTION_READ,
                &|tx| {
                    Box::pin(
                        async move { history_in(tx, ActionKind::FileCollection, id, limit).await },
                    )
                },
            )
            .await
    }

    /// Stops a collection that hasn't completed: it completes `CANCELLED`. One that has completed is a
    /// conflict: its result stands.
    pub async fn cancel_file_collection(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<ActionSummary, ServiceError> {
        self.gate
            .write(
                actor,
                "cancel_file_collection",
                &FILE_COLLECTION_WRITE,
                &|tx| {
                    Box::pin(async move {
                        let before = action_state(tx, ActionKind::FileCollection, id)
                            .await?
                            .ok_or_else(|| no_action(ActionKind::FileCollection, id))?;
                        if !core_actions::cancel_in(tx, id, "cancelled").await? {
                            return Err(ServiceError::Conflict(format!(
                                "file collection {id} has already completed"
                            )));
                        }
                        let after = action_state(tx, ActionKind::FileCollection, id)
                            .await?
                            .ok_or_else(|| no_action(ActionKind::FileCollection, id))?;
                        let change = Change::updated(Target::action(id), &before, &after)?;
                        Ok(Audited::changed(summary_in(tx, id).await?, change))
                    })
                },
            )
            .await
    }

    /// Starts a collection over: queued again with no tries counted and its time limit again, whatever its
    /// state, as ace3's retry does.
    pub async fn retry_file_collection(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<ActionSummary, ServiceError> {
        self.gate
            .write(
                actor,
                "retry_file_collection",
                &FILE_COLLECTION_WRITE,
                &|tx| {
                    Box::pin(async move {
                        let before = action_state(tx, ActionKind::FileCollection, id)
                            .await?
                            .ok_or_else(|| no_action(ActionKind::FileCollection, id))?;
                        core_actions::retry_in(tx, &self.actions, id).await?;
                        let after = action_state(tx, ActionKind::FileCollection, id)
                            .await?
                            .ok_or_else(|| no_action(ActionKind::FileCollection, id))?;
                        let change = Change::updated(Target::action(id), &before, &after)?;
                        Ok(Audited::changed(summary_in(tx, id).await?, change))
                    })
                },
            )
            .await
    }

    /// Deletes a collection and its tries, and lets go of its own hold on its file, which the alerts that
    /// asked for it keep. Returns it as it was.
    pub async fn delete_file_collection(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<ActionSummary, ServiceError> {
        self.gate
            .write(
                actor,
                "delete_file_collection",
                &FILE_COLLECTION_WRITE,
                &|tx| {
                    Box::pin(async move {
                        let before = action_state(tx, ActionKind::FileCollection, id)
                            .await?
                            .ok_or_else(|| no_action(ActionKind::FileCollection, id))?;
                        let summary = summary_in(tx, id).await?;
                        core_actions::delete_in(tx, id).await?;
                        let change = Change::removed(Target::action(id), &before)?;
                        Ok(Audited::changed(summary, change))
                    })
                },
            )
            .await
    }

    /// Lets go of the files of collections that completed more than their retention ago, in batches of
    /// `ace_core::actions::PRUNE_BATCH`, each a transaction with its audit row listing what it released.
    pub async fn prune_file_collections(
        &self,
        actor: &Actor,
    ) -> Result<CollectionsPruned, ServiceError> {
        let mut pruned = CollectionsPruned::default();
        let retention = core_actions::COLLECTION_RETENTION;
        loop {
            let released = self
                .gate
                .write(
                    actor,
                    "prune_file_collections",
                    &FILE_COLLECTION_PRUNE,
                    &|tx| {
                        Box::pin(async move {
                            let released =
                                core_actions::prune_collections_in(tx, retention).await?;
                            let count = released.len();
                            if released.is_empty() {
                                return Ok(Audited::unchanged(count));
                            }
                            let change = Change::removed(
                                Target::expired_collection_files(),
                                &Released {
                                    retention_days: retention.as_secs() / 86_400,
                                    collections: released,
                                },
                            )?;
                            Ok(Audited::changed(count, change))
                        })
                    },
                )
                .await?;
            pruned.released += released as u64;
            if released > 0 {
                pruned.batches += 1;
            }
            if i64::try_from(released).unwrap_or(i64::MAX) < core_actions::PRUNE_BATCH {
                return Ok(pruned);
            }
        }
    }
}
