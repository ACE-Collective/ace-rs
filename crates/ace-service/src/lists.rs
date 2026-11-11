//! Analyst-edited lists (PLAN.md 5.14, ace3 #1063, #1064): whitelists and the like, kept in Postgres
//! behind the API with an audit row for each change, in place of ace3's file-watched settings and
//! `saq/whitelist.py`.
//!
//! Which lists there are is the binary's: each is one its modules read (`ace_sdk::Module::LISTS`), so
//! the open-source build has the email module's two whitelists, and a site's modules bring theirs. A
//! list's entries are typed (`ace_sdk::lists`): an exact value, a substring or a regex, with or without
//! case, and on a typed list an observable type. Every entry is checked here as a module will compile
//! it, and the whole list with it, before the write commits: a pattern that doesn't compile with the
//! `regex` crate, or compiles too large, alone or with the list's others, is refused, and so is a list
//! past `MAX_ENTRIES`. A write locks the lists' version row first, so writes take turns and each checks
//! the list as committed.
//!
//! An edit applies to the next task that reads the list, with no restart: the write raises the lists'
//! version in its own transaction, and the lease API reads the version for each task it hands out
//! (`ace_core::lists`).
//!
//! Reading needs `list:read`, and adding, changing and deleting need `list:write`, both new: ace3 had no
//! permission for its files, and removed `whitelist:write` with its Whitelist action. Each write has an
//! audit row naming the actor, with the entry before and after; a delete's row keeps the whole entry.
//!
//! What differs from ace3:
//! - ace3's `smtp_from` and `smtp_to` whitelist entries are case-blind substrings. Here an entry says how
//!   it matches, so a substring entry with `ignore_case` is ace3's.
//! - ace3's file skipped a line it couldn't parse with an ERROR in the log, and kept the rest. Here a bad
//!   entry is refused when it's written, and a list a module receives always compiles.
//! - ace3's `http_host`, `http_src_ip` and `http_dest_ip` keys had no reader left in ace3, so they have no
//!   list here.

use std::collections::BTreeMap;

use ace_core::eligibility::Catalog;
use ace_results::ObservableKind;
use ace_sdk::lists::{Entry, InvalidEntry, List, ListSpec, MAX_ENTRIES, MAX_NOTE_CHARS, MatchKind};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use sqlx::types::Json;

use crate::actor::Actor;
use crate::alerts::RecordedActor;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{LIST_READ, LIST_WRITE};
use crate::{Service, ServiceError};

/// A list this binary's modules read, and how many entries it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSummary {
    pub spec: ListSpec,
    pub entries: i64,
}

/// One list, whole.
#[derive(Debug, Clone, PartialEq)]
pub struct ListView {
    pub spec: ListSpec,
    /// The lists' version these entries are at.
    pub version: i64,
    pub entries: Vec<ListEntry>,
}

/// An entry on a list, as an analyst sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct ListEntry {
    pub id: i64,
    pub list: String,
    pub kind: MatchKind,
    pub value: String,
    pub ignore_case: bool,
    pub observable_type: Option<String>,
    /// Why it's there.
    pub note: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: RecordedActor,
    pub created_at: DateTime<Utc>,
    pub updated_by: RecordedActor,
    pub updated_at: DateTime<Utc>,
}

/// What an entry holds, as a request gives it, for a new entry or in place of an entry's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewListEntry {
    pub kind: MatchKind,
    pub value: String,
    pub ignore_case: bool,
    pub observable_type: Option<String>,
    pub note: String,
    pub expires_at: Option<DateTime<Utc>>,
}

struct EntryRow {
    id: i64,
    list: String,
    kind: String,
    value: String,
    ignore_case: bool,
    observable_type: Option<String>,
    note: String,
    expires_at: Option<DateTime<Utc>>,
    created_by: Value,
    created_at: DateTime<Utc>,
    updated_by: Value,
    updated_at: DateTime<Utc>,
}

impl EntryRow {
    fn into_entry(self) -> Result<ListEntry, ServiceError> {
        let decode = |what: &str| ServiceError::from(ace_core::DbError::Decode(what.to_owned()));
        let kind = MatchKind::parse(&self.kind).ok_or_else(|| decode("a list entry's match"))?;
        Ok(ListEntry {
            id: self.id,
            list: self.list,
            kind,
            value: self.value,
            ignore_case: self.ignore_case,
            observable_type: self.observable_type,
            note: self.note,
            expires_at: self.expires_at,
            created_by: RecordedActor::from_row(Some(self.created_by))?
                .ok_or_else(|| decode("no actor"))?,
            created_at: self.created_at,
            updated_by: RecordedActor::from_row(Some(self.updated_by))?
                .ok_or_else(|| decode("no actor"))?,
            updated_at: self.updated_at,
        })
    }
}

impl ListEntry {
    fn as_sdk(&self) -> Entry {
        Entry {
            id: self.id,
            kind: self.kind,
            value: self.value.clone(),
            ignore_case: self.ignore_case,
            observable_type: self.observable_type.clone(),
            expires_at: self.expires_at,
        }
    }
}

/// An entry as its audit row records it.
#[derive(Serialize)]
struct RecordedEntry<'a> {
    list: &'a str,
    #[serde(rename = "match")]
    kind: &'static str,
    value: &'a str,
    ignore_case: bool,
    observable_type: Option<&'a str>,
    note: &'a str,
    expires_at: Option<DateTime<Utc>>,
}

impl Recorded for RecordedEntry<'_> {}

impl<'a> RecordedEntry<'a> {
    fn of(list: &'a str, entry: &'a NewListEntry) -> Self {
        RecordedEntry {
            list,
            kind: entry.kind.as_str(),
            value: &entry.value,
            ignore_case: entry.ignore_case,
            observable_type: entry.observable_type.as_deref(),
            note: &entry.note,
            expires_at: entry.expires_at,
        }
    }
}

/// A deleted entry, whole, since its row is gone.
#[derive(Serialize)]
struct RemovedEntry<'a> {
    #[serde(flatten)]
    entry: RecordedEntry<'a>,
    created_by: &'a Value,
    created_at: DateTime<Utc>,
}

impl Recorded for RemovedEntry<'_> {}

impl NewListEntry {
    fn of(entry: &ListEntry) -> Self {
        NewListEntry {
            kind: entry.kind,
            value: entry.value.clone(),
            ignore_case: entry.ignore_case,
            observable_type: entry.observable_type.clone(),
            note: entry.note.clone(),
            expires_at: entry.expires_at,
        }
    }

    /// The entry as it's stored: an observable type by its name, and checked as `spec`'s. An expiry
    /// has to be in the future, unless it's `kept`, an edited entry's own.
    fn checked(
        &self,
        spec: &ListSpec,
        now: DateTime<Utc>,
        kept: Option<DateTime<Utc>>,
    ) -> Result<NewListEntry, ServiceError> {
        let invalid = |e: InvalidEntry| ServiceError::InvalidRequest(e.to_string());
        let observable_type = match &self.observable_type {
            Some(kind) => Some(
                kind.parse::<ObservableKind>()
                    .map_err(|_| {
                        ServiceError::InvalidRequest(format!("no observable type {kind:?}"))
                    })?
                    .as_str()
                    .to_owned(),
            ),
            None => None,
        };
        if self.note.chars().count() > MAX_NOTE_CHARS || self.note.contains('\0') {
            return Err(ServiceError::InvalidRequest(format!(
                "a note is at most {MAX_NOTE_CHARS} characters, with no NUL"
            )));
        }
        if self
            .expires_at
            .is_some_and(|expires| expires <= now && Some(expires) != kept)
        {
            return Err(ServiceError::InvalidRequest(
                "an entry's expiry has to be in the future".to_owned(),
            ));
        }
        let entry = NewListEntry {
            observable_type,
            ..self.clone()
        };
        entry.as_sdk(0).check(spec).map_err(invalid)?;
        Ok(entry)
    }

    fn as_sdk(&self, id: i64) -> Entry {
        Entry {
            id,
            kind: self.kind,
            value: self.value.clone(),
            ignore_case: self.ignore_case,
            observable_type: self.observable_type.clone(),
            expires_at: self.expires_at,
        }
    }
}

/// The list `name` among the catalog's, or a 404.
pub(crate) fn spec(catalog: &Catalog, name: &str) -> Result<ListSpec, ServiceError> {
    catalog
        .lists()
        .get(name)
        .copied()
        .ok_or_else(|| ServiceError::NotFound(format!("no list {name:?}")))
}

fn no_entry(list: &str, id: i64) -> ServiceError {
    ServiceError::NotFound(format!("no entry {id} on list {list:?}"))
}

/// Locks the lists' version row, so writes take turns, and returns the version.
async fn lock_lists(conn: &mut PgConnection) -> Result<i64, ServiceError> {
    Ok(
        sqlx::query_scalar!("SELECT version FROM lists.version FOR UPDATE")
            .fetch_one(conn)
            .await?,
    )
}

async fn entries_of(conn: &mut PgConnection, list: &str) -> Result<Vec<ListEntry>, ServiceError> {
    sqlx::query_as!(
        EntryRow,
        r#"SELECT id, list, match AS kind, value, ignore_case, observable_type, note, expires_at,
                  created_by AS "created_by!: Value", created_at,
                  updated_by AS "updated_by!: Value", updated_at
           FROM lists.entries WHERE list = $1 ORDER BY id"#,
        list,
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(EntryRow::into_entry)
    .collect()
}

pub(crate) async fn entry_row(
    conn: &mut PgConnection,
    list: &str,
    id: i64,
) -> Result<ListEntry, ServiceError> {
    sqlx::query_as!(
        EntryRow,
        r#"SELECT id, list, match AS kind, value, ignore_case, observable_type, note, expires_at,
                  created_by AS "created_by!: Value", created_at,
                  updated_by AS "updated_by!: Value", updated_at
           FROM lists.entries WHERE list = $1 AND id = $2"#,
        list,
        id,
    )
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| no_entry(list, id))?
    .into_entry()
}

/// Checks the list as it would be with `entries`: the count, and its patterns together.
fn check_list(spec: &ListSpec, entries: &[Entry]) -> Result<(), ServiceError> {
    if entries.len() > MAX_ENTRIES {
        return Err(ServiceError::InvalidRequest(format!(
            "list {} holds at most {MAX_ENTRIES} entries",
            spec.name
        )));
    }
    List::check(spec, entries).map_err(|e| ServiceError::InvalidRequest(e.to_string()))
}

/// A unique violation as the conflict it is.
fn duplicate(error: sqlx::Error) -> ServiceError {
    let unique = error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation());
    if unique {
        ServiceError::Conflict(
            "the list has an entry with this match, case, type and value already".to_owned(),
        )
    } else {
        error.into()
    }
}

impl Service {
    /// The lists this binary's modules read, by name, with how many entries each has. It needs
    /// `list:read`.
    pub async fn lists(&self, actor: &Actor) -> Result<Vec<ListSummary>, ServiceError> {
        let specs = self.orchestrator.catalog().lists();
        let specs = &specs;
        self.gate
            .read(actor, "lists", &LIST_READ, &|tx| {
                Box::pin(async move {
                    let counts: BTreeMap<String, i64> = sqlx::query!(
                        r#"SELECT list, count(*) AS "count!" FROM lists.entries GROUP BY list"#
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| (row.list, row.count))
                    .collect();
                    Ok(specs
                        .values()
                        .map(|spec| ListSummary {
                            spec: *spec,
                            entries: counts.get(spec.name).copied().unwrap_or(0),
                        })
                        .collect())
                })
            })
            .await
    }

    /// A list and its entries in the order they were added, which is the order a module tries them.
    /// It needs `list:read`.
    pub async fn list(&self, actor: &Actor, name: &str) -> Result<ListView, ServiceError> {
        let spec = self.orchestrator.catalog().lists().get(name).copied();
        let spec = &spec;
        self.gate
            .read(actor, "list", &LIST_READ, &|tx| {
                Box::pin(async move {
                    let spec =
                        spec.ok_or_else(|| ServiceError::NotFound(format!("no list {name:?}")))?;
                    let version = sqlx::query_scalar!("SELECT version FROM lists.version")
                        .fetch_one(tx.conn())
                        .await?;
                    Ok(ListView {
                        spec,
                        version,
                        entries: entries_of(tx.conn(), spec.name).await?,
                    })
                })
            })
            .await
    }

    /// Adds an entry to the end of a list. It needs `list:write`, and applies to the next task that
    /// reads the list.
    pub async fn add_list_entry(
        &self,
        actor: &Actor,
        name: &str,
        entry: &NewListEntry,
    ) -> Result<ListEntry, ServiceError> {
        let catalog = self.orchestrator.catalog();
        self.gate
            .write(actor, "add_list_entry", &LIST_WRITE, &|tx| {
                Box::pin(async move {
                    let spec = spec(catalog, name)?;
                    let (added, change) = add_entry(tx.conn(), actor, &spec, entry).await?;
                    Ok(Audited::changed(added, change))
                })
            })
            .await
    }

    /// Replaces what an entry holds, keeping its place on the list. It needs `list:write`. An edit that
    /// changes nothing has no audit row.
    pub async fn edit_list_entry(
        &self,
        actor: &Actor,
        name: &str,
        id: i64,
        entry: &NewListEntry,
    ) -> Result<ListEntry, ServiceError> {
        let catalog = self.orchestrator.catalog();
        self.gate
            .write(actor, "edit_list_entry", &LIST_WRITE, &|tx| {
                Box::pin(async move {
                    let spec = spec(catalog, name)?;
                    let edited =
                        edit_entry(tx.conn(), actor, &spec, id, &|_| Ok(entry.clone())).await?;
                    Ok(match edited {
                        (entry, Some(change)) => Audited::changed(entry, change),
                        (entry, None) => Audited::unchanged(entry),
                    })
                })
            })
            .await
    }

    /// Deletes an entry. It needs `list:write`, and its audit row keeps the whole entry.
    pub async fn delete_list_entry(
        &self,
        actor: &Actor,
        name: &str,
        id: i64,
    ) -> Result<(), ServiceError> {
        let catalog = self.orchestrator.catalog();
        self.gate
            .write(actor, "delete_list_entry", &LIST_WRITE, &|tx| {
                Box::pin(async move {
                    let spec = spec(catalog, name)?;
                    let (_, change) = delete_entry(tx.conn(), &spec, id).await?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }
}

/// Adds `entry` to the end of `spec`'s list, in the caller's write: checked as a module will compile
/// it, alone and with the list's others, with the lists locked. It returns the entry and its audit
/// change. `add_list_entry` and the `detection` service's writes share it.
pub(crate) async fn add_entry(
    conn: &mut PgConnection,
    actor: &Actor,
    spec: &ListSpec,
    entry: &NewListEntry,
) -> Result<(ListEntry, Change), ServiceError> {
    let entry = entry.checked(spec, now(conn).await?, None)?;
    lock_lists(conn).await?;
    let mut entries: Vec<Entry> = entries_of(conn, spec.name)
        .await?
        .iter()
        .map(ListEntry::as_sdk)
        .collect();
    entries.push(entry.as_sdk(0));
    check_list(spec, &entries)?;
    let id = sqlx::query_scalar!(
        "INSERT INTO lists.entries
             (list, match, value, ignore_case, observable_type, note, expires_at,
              created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $8::jsonb)
         RETURNING id",
        spec.name,
        entry.kind.as_str(),
        entry.value,
        entry.ignore_case,
        entry.observable_type,
        entry.note,
        entry.expires_at,
        Json(actor) as _,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(duplicate)?;
    let added = entry_row(conn, spec.name, id).await?;
    let change = Change::added(
        Target::list_entry(id),
        &RecordedEntry::of(spec.name, &entry),
    )?;
    Ok((added, change))
}

/// Replaces what entry `id` of `spec`'s list holds with what `change` makes of it, in the caller's
/// write, keeping its place: checked as `add_entry` checks, with the lists locked. It returns the entry
/// and its audit change, which is None when nothing changed.
pub(crate) async fn edit_entry(
    conn: &mut PgConnection,
    actor: &Actor,
    spec: &ListSpec,
    id: i64,
    change: &(dyn Fn(&NewListEntry) -> Result<NewListEntry, ServiceError> + Sync),
) -> Result<(ListEntry, Option<Change>), ServiceError> {
    lock_lists(conn).await?;
    let current = entries_of(conn, spec.name).await?;
    let found = current
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| no_entry(spec.name, id))?;
    let before = NewListEntry::of(found);
    // an expiry that passed may stay as it was
    let entry = change(&before)?.checked(spec, now(conn).await?, before.expires_at)?;
    if entry == before {
        return Ok((found.clone(), None));
    }
    let entries: Vec<Entry> = current
        .iter()
        .map(|e| {
            if e.id == id {
                entry.as_sdk(id)
            } else {
                e.as_sdk()
            }
        })
        .collect();
    check_list(spec, &entries)?;
    sqlx::query!(
        "UPDATE lists.entries
         SET match = $3, value = $4, ignore_case = $5, observable_type = $6,
             note = $7, expires_at = $8, updated_by = $9::jsonb, updated_at = now()
         WHERE list = $1 AND id = $2",
        spec.name,
        id,
        entry.kind.as_str(),
        entry.value,
        entry.ignore_case,
        entry.observable_type,
        entry.note,
        entry.expires_at,
        Json(actor) as _,
    )
    .execute(&mut *conn)
    .await
    .map_err(duplicate)?;
    let edited = entry_row(conn, spec.name, id).await?;
    let change = Change::updated(
        Target::list_entry(id),
        &RecordedEntry::of(spec.name, &before),
        &RecordedEntry::of(spec.name, &entry),
    )?;
    Ok((edited, Some(change)))
}

/// Deletes entry `id` of `spec`'s list in the caller's write, with the lists locked. It returns the
/// entry as it was and its audit change, which keeps the whole entry.
pub(crate) async fn delete_entry(
    conn: &mut PgConnection,
    spec: &ListSpec,
    id: i64,
) -> Result<(ListEntry, Change), ServiceError> {
    lock_lists(conn).await?;
    let found = entry_row(conn, spec.name, id).await?;
    let created_by = sqlx::query_scalar!(
        r#"DELETE FROM lists.entries WHERE list = $1 AND id = $2
           RETURNING created_by AS "created_by!: Value""#,
        spec.name,
        id
    )
    .fetch_one(&mut *conn)
    .await?;
    let before = NewListEntry::of(&found);
    let change = Change::removed(
        Target::list_entry(id),
        &RemovedEntry {
            entry: RecordedEntry::of(spec.name, &before),
            created_by: &created_by,
            created_at: found.created_at,
        },
    )?;
    Ok((found, change))
}

/// The transaction's time, which every check of an expiry in one write uses.
pub(crate) async fn now(conn: &mut PgConnection) -> Result<DateTime<Utc>, ServiceError> {
    Ok(sqlx::query_scalar!(r#"SELECT now() AS "now!""#)
        .fetch_one(conn)
        .await?)
}
