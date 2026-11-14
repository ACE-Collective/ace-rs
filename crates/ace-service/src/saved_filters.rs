//! An analyst's saved filters (PLAN.md 5.10), ace3's `aceapi_v2/saved_filters` and its `SavedFilter` model:
//! a named filter list on one screen, which the list's quick-filter badges and its "Manage" dialog show.
//!
//! As in ace3:
//! - Every read and write needs the permission that reads the screen's data (`FilterScreen::permission`):
//!   a saved filter holds nothing its owner couldn't type into the filter bar. What keeps one analyst out of
//!   another's is the row's owner, checked here.
//! - A row is a person's. Its owner is the user, or the owner of the API key that wrote it, as ace3 takes a
//!   key's user. A key with no owner, or one of ACE's components, is refused with 403, as a comment is.
//! - Only the owner reads, changes or deletes a row. Another user's row is `NotFound` to a read and
//!   `Forbidden` to a write, ace3's 404 and 403.
//! - A name is unique per user and screen, and a second is `FilterNameTaken`, ace3's 409.
//! - The filters are checked for the row's screen (`filters::check`) and stored in their canonical spelling.
//! - Setting the quick filters takes the whole ordered list, numbers it from 0, and unpins the rest, so the
//!   call is idempotent.
//!
//! What differs: each write has an audit row, which ace3 doesn't write. A user has at most
//! `MAX_SAVED_FILTERS` on a screen, where ace3 has no bound. ace3's `working` and `temp` rows, and its
//! `PUT /scratch/{kind}`, hold the filter a page shows because ace3's session cookie can't: ace4's list
//! keeps it in the page's URL, so there's nothing to hold. ace3 seeds a new analyst's `Last 24h` and
//! `Last 7d`, which filter on the viewer's queue; they aren't seeded here, though 7.13 brought the queue
//! filter they need: a user here has no saved filters until they save one.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::actor::{Actor, UserId};
use crate::filters::{self, FilterEntry, FilterScreen};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most saved filters a user has on one screen.
pub const MAX_SAVED_FILTERS: i64 = 200;
/// The longest name, in characters, as ace3's.
pub const MAX_SAVED_FILTER_NAME_CHARS: usize = 255;
/// The longest description, in characters, as ace3's.
pub const MAX_SAVED_FILTER_DESCRIPTION_CHARS: usize = 1024;

/// One saved filter.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedFilter {
    pub id: Uuid,
    pub screen: FilterScreen,
    pub name: String,
    pub description: Option<String>,
    pub filters: Vec<FilterEntry>,
    /// Its place among the screen's quick filters, from 0, or None when it isn't one.
    pub quick_filter_order: Option<i32>,
    /// Whether its badge shows how many alerts it matches.
    pub quick_filter_indicator: bool,
    pub owner: UserId,
    pub owner_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A filter to save.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NewSavedFilter {
    pub name: String,
    pub description: Option<String>,
    pub filters: Vec<FilterEntry>,
    /// Pin it as the last quick filter.
    pub quick_filter: bool,
    pub quick_filter_indicator: bool,
}

/// What to change of a saved filter: each field that's Some.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SavedFilterChange {
    pub name: Option<String>,
    pub description: Option<String>,
    pub filters: Option<Vec<FilterEntry>>,
    pub quick_filter_indicator: Option<bool>,
}

/// A saved filter as its audit row records it.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct SavedFilterRecord {
    screen: &'static str,
    owner: Uuid,
    name: String,
    description: Option<String>,
    filters: Vec<FilterEntry>,
    quick_filter_order: Option<i32>,
    quick_filter_indicator: bool,
}

impl Recorded for SavedFilterRecord {}

impl SavedFilterRecord {
    fn of(filter: &SavedFilter) -> Self {
        SavedFilterRecord {
            screen: filter.screen.name(),
            owner: filter.owner.0,
            name: filter.name.clone(),
            description: filter.description.clone(),
            filters: filter.filters.clone(),
            quick_filter_order: filter.quick_filter_order,
            quick_filter_indicator: filter.quick_filter_indicator,
        }
    }
}

/// A screen's quick filters, in order, as `set_quick_filters`' row records them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct QuickFilters {
    pinned: Vec<Uuid>,
}

impl Recorded for QuickFilters {}

/// The user a saved filter of this actor's belongs to.
fn owner_of(actor: &Actor) -> Result<UserId, ServiceError> {
    match actor {
        Actor::User { id, .. } => Ok(*id),
        Actor::ApiKey {
            owner: Some(owner), ..
        } => Ok(*owner),
        Actor::ApiKey { owner: None, .. } | Actor::Internal { .. } => {
            Err(ServiceError::Forbidden(
                "a saved filter is a person's: an API key with no owner, or one of ACE's components, has none"
                    .to_owned(),
            ))
        }
    }
}

fn checked_name(name: &str) -> Result<&str, ServiceError> {
    let count = name.chars().count();
    if name.trim().is_empty() || count > MAX_SAVED_FILTER_NAME_CHARS || name.contains('\0') {
        return Err(ServiceError::InvalidRequest(format!(
            "a saved filter's name is 1 to {MAX_SAVED_FILTER_NAME_CHARS} characters, not all whitespace"
        )));
    }
    Ok(name)
}

fn checked_description(description: &str) -> Result<&str, ServiceError> {
    if description.chars().count() > MAX_SAVED_FILTER_DESCRIPTION_CHARS
        || description.contains('\0')
    {
        return Err(ServiceError::InvalidRequest(format!(
            "a saved filter's description is at most {MAX_SAVED_FILTER_DESCRIPTION_CHARS} characters"
        )));
    }
    Ok(description)
}

/// A filter list to save on `screen`: checked, canonical and not empty, as ace3's `min_length=1`.
fn checked_filters(
    screen: FilterScreen,
    entries: &[FilterEntry],
) -> Result<Vec<FilterEntry>, ServiceError> {
    let entries = filters::check(screen, entries)?;
    if entries.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "a saved filter has at least one filter".to_owned(),
        ));
    }
    Ok(entries)
}

fn no_filter(id: Uuid) -> ServiceError {
    ServiceError::NotFound(format!("no saved filter {id}"))
}

struct Row {
    id: Uuid,
    user_id: Uuid,
    username: String,
    display_name: Option<String>,
    screen: String,
    name: String,
    description: Option<String>,
    filters: Value,
    quick_filter_order: Option<i32>,
    quick_filter_indicator: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Row {
    fn into_filter(self) -> Result<SavedFilter, ServiceError> {
        let decode = |what: &str| {
            ServiceError::from(ace_core::DbError::Decode(format!(
                "a saved filter's {what}"
            )))
        };
        let screen = FilterScreen::named(&self.screen).ok_or_else(|| decode("screen"))?;
        // the stored list is read as it was saved; the list it's applied to checks it again, so a filter a
        // later release drops is refused there, saying why, rather than hiding the row
        let filters: Vec<FilterEntry> =
            serde_json::from_value(self.filters).map_err(|_| decode("filters"))?;
        Ok(SavedFilter {
            id: self.id,
            screen,
            name: self.name,
            description: self.description,
            filters,
            quick_filter_order: self.quick_filter_order,
            quick_filter_indicator: self.quick_filter_indicator,
            owner: UserId(self.user_id),
            owner_name: self.display_name.unwrap_or(self.username),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

async fn row(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    lock: bool,
) -> Result<Option<Row>, ServiceError> {
    let row = if lock {
        sqlx::query_as!(
            Row,
            r#"SELECT f.id, f.user_id, u.username::text AS "username!", u.display_name, f.screen, f.name,
                      f.description, f.filters, f.quick_filter_order, f.quick_filter_indicator,
                      f.created_at, f.updated_at
               FROM service.saved_filters f JOIN service.users u ON u.id = f.user_id
               WHERE f.id = $1 FOR UPDATE OF f"#,
            id,
        )
        .fetch_optional(conn)
        .await?
    } else {
        sqlx::query_as!(
            Row,
            r#"SELECT f.id, f.user_id, u.username::text AS "username!", u.display_name, f.screen, f.name,
                      f.description, f.filters, f.quick_filter_order, f.quick_filter_indicator,
                      f.created_at, f.updated_at
               FROM service.saved_filters f JOIN service.users u ON u.id = f.user_id
               WHERE f.id = $1"#,
            id,
        )
        .fetch_optional(conn)
        .await?
    };
    Ok(row)
}

async fn rows_of(
    conn: &mut sqlx::PgConnection,
    owner: UserId,
    screen: FilterScreen,
) -> Result<Vec<SavedFilter>, ServiceError> {
    sqlx::query_as!(
        Row,
        r#"SELECT f.id, f.user_id, u.username::text AS "username!", u.display_name, f.screen, f.name,
                  f.description, f.filters, f.quick_filter_order, f.quick_filter_indicator,
                  f.created_at, f.updated_at
           FROM service.saved_filters f JOIN service.users u ON u.id = f.user_id
           WHERE f.user_id = $1 AND f.screen = $2
           ORDER BY f.quick_filter_order IS NULL, f.quick_filter_order, f.name, f.id"#,
        owner.0,
        screen.name(),
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(Row::into_filter)
    .collect()
}

/// The row, locked, refused unless the actor owns it.
async fn own_row(
    conn: &mut sqlx::PgConnection,
    actor: &Actor,
    id: Uuid,
) -> Result<SavedFilter, ServiceError> {
    let found = row(conn, id, true).await?.ok_or_else(|| no_filter(id))?;
    if owner_of(actor)?.0 != found.user_id {
        return Err(ServiceError::Forbidden(
            "this saved filter belongs to another user".to_owned(),
        ));
    }
    found.into_filter()
}

fn name_taken(error: sqlx::Error, name: &str) -> ServiceError {
    let taken = error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation());
    if taken {
        ServiceError::FilterNameTaken(name.to_owned())
    } else {
        error.into()
    }
}

impl Service {
    /// The caller's saved filters on a screen: the quick filters first, in their order, then the rest by
    /// name. It needs the screen's permission.
    pub async fn saved_filters(
        &self,
        actor: &Actor,
        screen: FilterScreen,
    ) -> Result<Vec<SavedFilter>, ServiceError> {
        self.gate
            .read(actor, "saved_filters", &screen.permission(), &|tx| {
                Box::pin(async move {
                    let owner = owner_of(actor)?;
                    rows_of(tx.conn(), owner, screen).await
                })
            })
            .await
    }

    /// One of the caller's saved filters. Someone else's is `NotFound`, as in ace3: sharing is a link, not
    /// a row.
    pub async fn saved_filter(&self, actor: &Actor, id: Uuid) -> Result<SavedFilter, ServiceError> {
        // every screen reads with alert:read; a screen that doesn't needs its row's screen checked first
        self.gate
            .read(actor, "saved_filter", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let owner = owner_of(actor)?;
                    match row(tx.conn(), id, false).await? {
                        Some(found) if found.user_id == owner.0 => found.into_filter(),
                        _ => Err(no_filter(id)),
                    }
                })
            })
            .await
    }

    /// Saves a filter list on a screen for the caller, as the last quick filter when asked. It needs the
    /// screen's permission.
    pub async fn create_saved_filter(
        &self,
        actor: &Actor,
        screen: FilterScreen,
        new: &NewSavedFilter,
    ) -> Result<SavedFilter, ServiceError> {
        let name = checked_name(&new.name)?;
        let description = new
            .description
            .as_deref()
            .map(checked_description)
            .transpose()?;
        let filters = checked_filters(screen, &new.filters)?;
        let stored = &serde_json::to_value(&filters)?;
        let quick = new.quick_filter;
        let indicator = new.quick_filter_indicator;
        self.gate
            .write(actor, "create_saved_filter", &screen.permission(), &|tx| {
                Box::pin(async move {
                    let owner = owner_of(actor)?;
                    // one user's saves are one at a time, so the bound and the next order hold
                    sqlx::query!(
                        "SELECT id FROM service.users WHERE id = $1 FOR UPDATE",
                        owner.0
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or(ServiceError::NoUser(owner.0))?;
                    let counts = sqlx::query!(
                        r#"SELECT count(*) AS "count!", max(quick_filter_order) AS last
                           FROM service.saved_filters WHERE user_id = $1 AND screen = $2"#,
                        owner.0,
                        screen.name(),
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    if counts.count >= MAX_SAVED_FILTERS {
                        return Err(ServiceError::InvalidRequest(format!(
                            "a user has at most {MAX_SAVED_FILTERS} saved filters on a screen"
                        )));
                    }
                    let order = quick.then(|| counts.last.map_or(0, |last| last + 1));
                    let id = Uuid::new_v4();
                    sqlx::query!(
                        "INSERT INTO service.saved_filters
                             (id, user_id, screen, name, description, filters, quick_filter_order,
                              quick_filter_indicator)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                        id,
                        owner.0,
                        screen.name(),
                        name,
                        description,
                        stored,
                        order,
                        indicator,
                    )
                    .execute(tx.conn())
                    .await
                    .map_err(|error| name_taken(error, name))?;
                    let saved = row(tx.conn(), id, false)
                        .await?
                        .ok_or_else(|| no_filter(id))?
                        .into_filter()?;
                    let change =
                        Change::added(Target::saved_filter(id), &SavedFilterRecord::of(&saved))?;
                    Ok(Audited::changed(saved, change))
                })
            })
            .await
    }

    /// Changes one of the caller's saved filters: each field the change has. Its filters are checked for
    /// the row's own screen. A change to what it already is changes nothing.
    pub async fn update_saved_filter(
        &self,
        actor: &Actor,
        id: Uuid,
        change: &SavedFilterChange,
    ) -> Result<SavedFilter, ServiceError> {
        if let Some(name) = &change.name {
            checked_name(name)?;
        }
        if let Some(description) = &change.description {
            checked_description(description)?;
        }
        self.gate
            .write(actor, "update_saved_filter", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let before = own_row(tx.conn(), actor, id).await?;
                    let filters = change
                        .filters
                        .as_deref()
                        .map(|filters| checked_filters(before.screen, filters))
                        .transpose()?;
                    let mut after = before.clone();
                    if let Some(name) = &change.name {
                        after.name = name.clone();
                    }
                    if let Some(description) = &change.description {
                        after.description = Some(description.clone());
                    }
                    if let Some(filters) = filters {
                        after.filters = filters;
                    }
                    if let Some(indicator) = change.quick_filter_indicator {
                        after.quick_filter_indicator = indicator;
                    }
                    let (was, now) = (
                        SavedFilterRecord::of(&before),
                        SavedFilterRecord::of(&after),
                    );
                    if was == now {
                        return Ok(Audited::unchanged(before));
                    }
                    let stored = serde_json::to_value(&after.filters)?;
                    sqlx::query!(
                        "UPDATE service.saved_filters
                         SET name = $2, description = $3, filters = $4, quick_filter_indicator = $5,
                             updated_at = now()
                         WHERE id = $1",
                        id,
                        after.name,
                        after.description,
                        stored,
                        after.quick_filter_indicator,
                    )
                    .execute(tx.conn())
                    .await
                    .map_err(|error| name_taken(error, &after.name))?;
                    let saved = row(tx.conn(), id, false)
                        .await?
                        .ok_or_else(|| no_filter(id))?
                        .into_filter()?;
                    let change = Change::updated(Target::saved_filter(id), &was, &now)?;
                    Ok(Audited::changed(saved, change))
                })
            })
            .await
    }

    /// Deletes one of the caller's saved filters. Its audit row keeps it.
    pub async fn delete_saved_filter(&self, actor: &Actor, id: Uuid) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "delete_saved_filter", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let found = own_row(tx.conn(), actor, id).await?;
                    sqlx::query!("DELETE FROM service.saved_filters WHERE id = $1", id)
                        .execute(tx.conn())
                        .await?;
                    let change =
                        Change::removed(Target::saved_filter(id), &SavedFilterRecord::of(&found))?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// Makes these of the caller's saved filters the screen's quick filters, in this order, and unpins the
    /// rest. An id that isn't one of the caller's filters on the screen is `InvalidRequest`, as ace3's 400.
    pub async fn set_quick_filters(
        &self,
        actor: &Actor,
        screen: FilterScreen,
        ids: &[Uuid],
    ) -> Result<Vec<SavedFilter>, ServiceError> {
        let mut seen = std::collections::HashSet::new();
        if let Some(repeated) = ids.iter().find(|id| !seen.insert(**id)) {
            return Err(ServiceError::InvalidRequest(format!(
                "{repeated} is listed twice"
            )));
        }
        self.gate
            .write(actor, "set_quick_filters", &screen.permission(), &|tx| {
                Box::pin(async move {
                    let owner = owner_of(actor)?;
                    sqlx::query!(
                        "SELECT id FROM service.users WHERE id = $1 FOR UPDATE",
                        owner.0
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or(ServiceError::NoUser(owner.0))?;
                    let rows = rows_of(tx.conn(), owner, screen).await?;
                    if let Some(unknown) = ids.iter().find(|id| !rows.iter().any(|row| row.id == **id)) {
                        return Err(ServiceError::InvalidRequest(format!(
                            "{unknown} isn't one of your saved filters on the {screen} screen"
                        )));
                    }
                    let pinned = |rows: &[SavedFilter]| QuickFilters {
                        pinned: rows
                            .iter()
                            .filter(|row| row.quick_filter_order.is_some())
                            .map(|row| row.id)
                            .collect(),
                    };
                    let before = pinned(&rows);
                    let orders: Vec<i32> = (0..ids.len())
                        .map(|at| i32::try_from(at).unwrap_or(i32::MAX))
                        .collect();
                    let dense = rows.iter().all(|row| {
                        row.quick_filter_order
                            == ids.iter().position(|id| *id == row.id).map(|at| orders[at])
                    });
                    if dense {
                        return Ok(Audited::unchanged(rows));
                    }
                    sqlx::query!(
                        "UPDATE service.saved_filters f
                         SET quick_filter_order = o.n, updated_at = now()
                         FROM (SELECT id, (n - 1)::integer AS n
                               FROM unnest($3::uuid[]) WITH ORDINALITY AS o(id, n)) o
                         WHERE f.user_id = $1 AND f.screen = $2 AND f.id = o.id
                           AND f.quick_filter_order IS DISTINCT FROM o.n",
                        owner.0,
                        screen.name(),
                        ids,
                    )
                    .execute(tx.conn())
                    .await?;
                    sqlx::query!(
                        "UPDATE service.saved_filters SET quick_filter_order = NULL, updated_at = now()
                         WHERE user_id = $1 AND screen = $2 AND quick_filter_order IS NOT NULL
                           AND id <> ALL ($3::uuid[])",
                        owner.0,
                        screen.name(),
                        ids,
                    )
                    .execute(tx.conn())
                    .await?;
                    let rows = rows_of(tx.conn(), owner, screen).await?;
                    let change = Change::updated(
                        Target::quick_filters(owner.0, screen.name()),
                        &before,
                        &pinned(&rows),
                    )?;
                    Ok(Audited::changed(rows, change))
                })
            })
            .await
    }
}
