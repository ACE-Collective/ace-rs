//! What the core reads of the analyst-edited lists (PLAN.md 5.14) for a module's leased task.
//!
//! The entries are in `lists.entries`, which the service writes (migration 0033). A worker holds no
//! database credentials, so the lease API adds the lists a module reads (`Module::LISTS`) to each of
//! its tasks (`wire::LeasedTask::lists`) as they are when it hands the task out.
//!
//! Every committed write raises `lists.version` in the write's own transaction. `ListCache` keeps the
//! last snapshot it read with its version, and for each lease reads only the version, a one-row
//! lookup, after the task is claimed. When the version read is newer than the snapshot's, it reads the
//! snapshot again, the version and every entry in one statement, so the two agree. A task leased after
//! an edit committed therefore always carries the edit: the lease's read of the version comes after the
//! commit, and a snapshot is used only when it's at least that new. Nothing waits on a notification,
//! so a lost one can't leave a list stale, and the cost bounded by `ace_sdk::lists::MAX_ENTRIES` is paid
//! once per edit, not per lease.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ace_sdk::lists::{Entry, ListSpec, MatchKind, WireList};
use sqlx::PgPool;

use crate::db::DbError;

/// Every list's entries at one version.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub version: i64,
    /// By list name, each in id order.
    pub lists: BTreeMap<String, Vec<Entry>>,
}

impl Snapshot {
    /// The lists `specs` names, as a task carries them. A list with no entries is sent empty.
    pub fn wire(&self, specs: &[ListSpec]) -> Vec<WireList> {
        specs
            .iter()
            .map(|spec| WireList {
                name: spec.name.to_owned(),
                version: self.version,
                entries: self.lists.get(spec.name).cloned().unwrap_or_default(),
            })
            .collect()
    }
}

/// The lists' version: it rises with every committed write to any entry.
pub async fn version(pool: &PgPool) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!("SELECT version FROM lists.version")
        .fetch_one(pool)
        .await?)
}

/// Every entry and the version they're at, read in one statement so they agree.
pub async fn snapshot(pool: &PgPool) -> Result<Snapshot, DbError> {
    let rows = sqlx::query!(
        r#"SELECT v.version, e.id AS "id?", e.list AS "list?", e.match AS "kind?",
                  e.value AS "value?", e.ignore_case AS "ignore_case?",
                  e.observable_type, e.expires_at
           FROM lists.version v LEFT JOIN lists.entries e ON true
           ORDER BY e.list, e.id"#
    )
    .fetch_all(pool)
    .await?;
    let mut snapshot = Snapshot::default();
    for row in rows {
        snapshot.version = row.version;
        let (Some(id), Some(list), Some(kind), Some(value), Some(ignore_case)) =
            (row.id, row.list, row.kind, row.value, row.ignore_case)
        else {
            continue;
        };
        let kind = MatchKind::parse(&kind)
            .ok_or_else(|| DbError::Decode(format!("list entry {id}: match {kind:?}")))?;
        snapshot.lists.entry(list).or_default().push(Entry {
            id,
            kind,
            value,
            ignore_case,
            observable_type: row.observable_type,
            expires_at: row.expires_at,
        });
    }
    Ok(snapshot)
}

/// The last snapshot read, shared by every lease the API hands out.
#[derive(Debug, Default)]
pub struct ListCache {
    last: Mutex<Option<Arc<Snapshot>>>,
}

impl ListCache {
    /// A snapshot at least as new as every write committed before this call.
    pub async fn current(&self, pool: &PgPool) -> Result<Arc<Snapshot>, DbError> {
        let version = version(pool).await?;
        if let Some(last) = self.cached()
            && last.version >= version
        {
            return Ok(last);
        }
        let fresh = Arc::new(snapshot(pool).await?);
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        // another lease may have read a newer one meanwhile
        match last.as_ref() {
            Some(kept) if kept.version >= fresh.version => Ok(kept.clone()),
            _ => {
                *last = Some(fresh.clone());
                Ok(fresh)
            }
        }
    }

    fn cached(&self) -> Option<Arc<Snapshot>> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
