//! Analysts' comments on an observable (PLAN.md 5.6's `observable_comments`), ace3's
//! `aceapi_v2/observable_comments` and its `ObservableComment` model.
//!
//! A comment is on an observable's type and value, not on one alert's observable, so it applies to that
//! observable in every alert, as ace3's does through its index of every observable. ace-rs has no such
//! index: a comment holds the type and the value, normalized as 5.5's lookup normalizes them (a file's
//! sha256 lowercased, anything else as given), and is matched as the lookup matches, by type, value hash
//! and value. A type this binary doesn't have is refused, as ace3 refuses one its registry doesn't
//! publish.
//!
//! As in ace3:
//! - Reading needs `observable:read`, and adding, editing and deleting need `observable:write`.
//! - A comment is a person's. Its author is the user, or the owner of the API key that wrote it, as
//!   ace3 records a key's user. A key with no owner, or one of ACE's components, has no user to be the
//!   author, and is refused with 403 where ace3 answers 401.
//! - Only the author edits or deletes a comment, with any of their credentials that holds
//!   `observable:write`. An admin can't either: ace3 has no override, so neither does this.
//! - A comment is stored with its line breaks normalized (`normalize_comment`): a form post sends CRLF
//!   and the edit box LF, trimmed. So an edit whose text normalizes to what's stored isn't a change: it
//!   has no audit row and doesn't mark the comment edited. Migration 0090 normalized the comments
//!   stored before (ace3 130b9e3c).
//! - A delete removes the row. Its audit row keeps the whole comment.
//!
//! What differs: ace3 takes any text. Here a comment holds 1 to `MAX_COMMENT_CHARS` characters, ace3's
//! limit on an SVS run's comment, with something besides whitespace, as ace3's GUI asks, and no NUL,
//! which Postgres can't store. Past its line breaks, the text is stored and returned as it was sent:
//! it's data, and a page that shows it escapes it.
//!
//! The alert view (5.8) shows each observable's comments, as ace3's does: `alert_observable_comments`
//! reads an alert's in one query, under `alert:read` as the alert's other reads are. 5.5's lookup could
//! count them too, through the same index, but ace3's doesn't, so it doesn't yet.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use crate::actor::{Actor, UserId};
use crate::alerts::RecordedActor;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::observables::normalized;
use crate::permission::{ALERT_READ, OBSERVABLE_READ, OBSERVABLE_WRITE};
use crate::{Service, ServiceError};

/// The longest comment, in characters: ace3's limit on an SVS run's comment, since its own has none.
pub const MAX_COMMENT_CHARS: usize = 16384;

/// The user a comment is by, as they're called now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentAuthor {
    pub id: UserId,
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObservableComment {
    pub id: i64,
    pub kind: String,
    /// The value as it's matched, such as a lowercased sha256.
    pub value: String,
    pub author: CommentAuthor,
    /// The actor that wrote it: the author, or one of their keys.
    pub created_by: RecordedActor,
    pub comment: String,
    pub created_at: DateTime<Utc>,
    /// When the text last changed; None when it never has.
    pub edited_at: Option<DateTime<Utc>>,
}

pub(crate) struct CommentRow {
    pub(crate) id: i64,
    pub(crate) kind: String,
    pub(crate) value: String,
    pub(crate) author_id: Uuid,
    pub(crate) username: String,
    pub(crate) display_name: Option<String>,
    pub(crate) created_by: Value,
    pub(crate) comment: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) edited_at: Option<DateTime<Utc>>,
}

impl CommentRow {
    pub(crate) fn into_comment(self) -> Result<ObservableComment, ServiceError> {
        let created_by = RecordedActor::from_row(Some(self.created_by))?
            .ok_or_else(|| ServiceError::from(ace_core::DbError::Decode("no actor".to_owned())))?;
        Ok(ObservableComment {
            id: self.id,
            kind: self.kind,
            value: self.value,
            author: CommentAuthor {
                id: UserId(self.author_id),
                username: self.username,
                display_name: self.display_name,
            },
            created_by,
            comment: self.comment,
            created_at: self.created_at,
            edited_at: self.edited_at,
        })
    }
}

/// A comment as its audit row records it when it's added.
#[derive(Serialize)]
struct AddedComment<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: &'a str,
    author: Uuid,
    comment: &'a str,
}

impl Recorded for AddedComment<'_> {}

/// A deleted comment, whole, since its row is gone.
#[derive(Serialize)]
struct RemovedComment<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: &'a str,
    author: Uuid,
    comment: &'a str,
    created_by: &'a Value,
    created_at: DateTime<Utc>,
    edited_at: Option<DateTime<Utc>>,
}

impl Recorded for RemovedComment<'_> {}

/// An edit's before and after.
#[derive(Serialize)]
struct CommentText<'a> {
    comment: &'a str,
}

impl Recorded for CommentText<'_> {}

/// What an edit's row says the comment is on.
#[derive(Serialize)]
struct CommentOn<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: &'a str,
    author: Uuid,
}

impl Recorded for CommentOn<'_> {}

/// The user a comment by this actor is by.
fn author_of(actor: &Actor) -> Result<UserId, ServiceError> {
    match actor {
        Actor::User { id, .. } => Ok(*id),
        Actor::ApiKey {
            owner: Some(owner), ..
        } => Ok(*owner),
        Actor::ApiKey { owner: None, .. } | Actor::Internal { .. } => {
            Err(ServiceError::Forbidden(
                "a comment is a person's: an API key with no owner, or one of ACE's components, can't write one"
                    .to_owned(),
            ))
        }
    }
}

/// The (type, value) a comment is matched by, or why the pair can't have one.
fn observable(kind: &str, value: &str) -> Result<(String, String), ServiceError> {
    let (kind, value) = normalized(kind, value).map_err(ServiceError::InvalidRequest)?;
    if value.contains('\0') {
        return Err(ServiceError::InvalidRequest(
            "an observable's value can't hold a NUL character".to_owned(),
        ));
    }
    Ok((kind.as_str().to_owned(), value))
}

/// A comment's text as it's stored, ace3's `normalize_comment`: CRLF line breaks as LF and no
/// whitespace at its ends, as Python's `strip` takes it. A form post sends CRLF and the edit box LF,
/// trimmed, so storing one form makes an unchanged edit equal to the stored text.
pub(crate) fn normalize_comment(text: &str) -> String {
    ace_pycompat::pystr::strip(&text.replace("\r\n", "\n")).to_owned()
}

/// The comment normalized, or why it can't be stored.
fn checked(text: &str) -> Result<String, ServiceError> {
    let text = normalize_comment(text);
    if text.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "a comment can't be empty".to_owned(),
        ));
    }
    if text.chars().count() > MAX_COMMENT_CHARS {
        return Err(ServiceError::InvalidRequest(format!(
            "a comment is at most {MAX_COMMENT_CHARS} characters"
        )));
    }
    if text.contains('\0') {
        return Err(ServiceError::InvalidRequest(
            "a comment can't hold a NUL character".to_owned(),
        ));
    }
    Ok(text)
}

fn no_comment(id: i64) -> ServiceError {
    ServiceError::NotFound(format!("no comment {id}"))
}

async fn comment_row(conn: &mut PgConnection, id: i64) -> Result<ObservableComment, ServiceError> {
    sqlx::query_as!(
        CommentRow,
        r#"SELECT c.id, c.type AS kind, c.value, c.author_id, u.username::text AS "username!",
                  u.display_name, c.created_by AS "created_by!: Value", c.comment, c.created_at,
                  c.edited_at
           FROM analysis.observable_comments c JOIN service.users u ON u.id = c.author_id
           WHERE c.id = $1"#,
        id,
    )
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| no_comment(id))?
    .into_comment()
}

/// The comment, locked for this transaction, refused unless the actor is its author.
async fn own_comment(
    conn: &mut PgConnection,
    actor: &Actor,
    id: i64,
) -> Result<CommentRow, ServiceError> {
    let found = sqlx::query_as!(
        CommentRow,
        r#"SELECT c.id, c.type AS kind, c.value, c.author_id, u.username::text AS "username!",
                  u.display_name, c.created_by AS "created_by!: Value", c.comment, c.created_at,
                  c.edited_at
           FROM analysis.observable_comments c JOIN service.users u ON u.id = c.author_id
           WHERE c.id = $1
           FOR UPDATE OF c"#,
        id,
    )
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| no_comment(id))?;
    if author_of(actor).ok() != Some(UserId(found.author_id)) {
        return Err(ServiceError::Forbidden(
            "only a comment's author can change or delete it".to_owned(),
        ));
    }
    Ok(found)
}

impl Service {
    /// The comments on an observable, oldest first, from every alert. ace3's list isn't paged: an
    /// observable has a few.
    pub async fn observable_comments(
        &self,
        actor: &Actor,
        kind: &str,
        value: &str,
    ) -> Result<Vec<ObservableComment>, ServiceError> {
        let (kind, value) = observable(kind, value)?;
        let (kind, value) = (&kind, &value);
        self.gate
            .read(actor, "observable_comments", &OBSERVABLE_READ, &|tx| {
                Box::pin(async move {
                    sqlx::query_as!(
                        CommentRow,
                        r#"SELECT c.id, c.type AS kind, c.value, c.author_id,
                                  u.username::text AS "username!", u.display_name,
                                  c.created_by AS "created_by!: Value", c.comment, c.created_at,
                                  c.edited_at
                           FROM analysis.observable_comments c
                           JOIN service.users u ON u.id = c.author_id
                           WHERE c.type = $1 AND c.value_hash = analysis.value_hash($2)
                             AND c.value = $2
                           ORDER BY c.created_at, c.id"#,
                        kind,
                        value,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(CommentRow::into_comment)
                    .collect()
                })
            })
            .await
    }

    /// The comments on any of an alert's observables, oldest first, for the alert view (5.8), as ace3's
    /// alert page and its `comments.json` gather them. It needs `alert:read`.
    pub async fn alert_observable_comments(
        &self,
        actor: &Actor,
        root: Uuid,
    ) -> Result<Vec<ObservableComment>, ServiceError> {
        self.gate
            .read(actor, "alert_observable_comments", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let alert = sqlx::query_scalar!(
                        "SELECT alerted_at IS NOT NULL FROM analysis.roots WHERE id = $1",
                        root,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .flatten();
                    if alert != Some(true) {
                        return Err(ServiceError::NotFound(format!("no alert {root}")));
                    }
                    sqlx::query_as!(
                        CommentRow,
                        r#"SELECT c.id, c.type AS kind, c.value, c.author_id,
                                  u.username::text AS "username!", u.display_name,
                                  c.created_by AS "created_by!: Value", c.comment, c.created_at,
                                  c.edited_at
                           FROM analysis.observable_comments c
                           JOIN service.users u ON u.id = c.author_id
                           WHERE EXISTS (SELECT FROM analysis.observables o
                                         WHERE o.root_id = $1 AND o.type = c.type
                                           AND o.value_hash = c.value_hash AND o.value = c.value)
                           ORDER BY c.created_at, c.id"#,
                        root,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(CommentRow::into_comment)
                    .collect()
                })
            })
            .await
    }

    /// Comments on an observable by its type and value, whether or not any alert holds it yet, as ace3's
    /// does. It needs `observable:write`, and the actor has to be a person (the module's docs).
    pub async fn add_observable_comment(
        &self,
        actor: &Actor,
        kind: &str,
        value: &str,
        comment: &str,
    ) -> Result<ObservableComment, ServiceError> {
        let (kind, value) = observable(kind, value)?;
        let comment = checked(comment)?;
        let (kind, value, comment) = (&kind, &value, comment.as_str());
        self.gate
            .write(actor, "add_observable_comment", &OBSERVABLE_WRITE, &|tx| {
                Box::pin(async move {
                    let author = author_of(actor)?;
                    let id = sqlx::query_scalar!(
                        "INSERT INTO analysis.observable_comments
                             (type, value, author_id, created_by, comment)
                         VALUES ($1, $2, $3, $4::jsonb, $5)
                         RETURNING id",
                        kind,
                        value,
                        author.0,
                        Json(actor) as _,
                        comment,
                    )
                    .fetch_one(tx.conn())
                    .await
                    .map_err(|error| {
                        let missing = error
                            .as_database_error()
                            .is_some_and(|error| error.is_foreign_key_violation());
                        if missing {
                            ServiceError::NoUser(author.0)
                        } else {
                            error.into()
                        }
                    })?;
                    let added = comment_row(tx.conn(), id).await?;
                    let change = Change::added(
                        Target::observable_comment(id),
                        &AddedComment {
                            kind,
                            value,
                            author: author.0,
                            comment,
                        },
                    )?;
                    Ok(Audited::changed(added, change))
                })
            })
            .await
    }

    /// Replaces a comment's text and marks it edited. It needs `observable:write`, and only the author
    /// may. Text that normalizes to the stored text (`normalize_comment`) changes nothing.
    pub async fn edit_observable_comment(
        &self,
        actor: &Actor,
        id: i64,
        comment: &str,
    ) -> Result<ObservableComment, ServiceError> {
        let comment = checked(comment)?;
        let comment = comment.as_str();
        self.gate
            .write(actor, "edit_observable_comment", &OBSERVABLE_WRITE, &|tx| {
                Box::pin(async move {
                    let found = own_comment(tx.conn(), actor, id).await?;
                    // stored comments are normalized, so text that normalizes to it is no change
                    if found.comment == comment {
                        return Ok(Audited::unchanged(found.into_comment()?));
                    }
                    sqlx::query!(
                        "UPDATE analysis.observable_comments SET comment = $2, edited_at = now()
                         WHERE id = $1",
                        id,
                        comment,
                    )
                    .execute(tx.conn())
                    .await?;
                    let edited = comment_row(tx.conn(), id).await?;
                    let change = Change::updated(
                        Target::observable_comment(id),
                        &CommentText {
                            comment: &found.comment,
                        },
                        &CommentText { comment },
                    )?
                    .details(&CommentOn {
                        kind: &found.kind,
                        value: &found.value,
                        author: found.author_id,
                    })?;
                    Ok(Audited::changed(edited, change))
                })
            })
            .await
    }

    /// Deletes a comment, as ace3 does: the row goes, and its audit row keeps it. It needs
    /// `observable:write`, and only the author may.
    pub async fn delete_observable_comment(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<(), ServiceError> {
        self.gate
            .write(
                actor,
                "delete_observable_comment",
                &OBSERVABLE_WRITE,
                &|tx| {
                    Box::pin(async move {
                        let found = own_comment(tx.conn(), actor, id).await?;
                        sqlx::query!("DELETE FROM analysis.observable_comments WHERE id = $1", id)
                            .execute(tx.conn())
                            .await?;
                        let change = Change::removed(
                            Target::observable_comment(id),
                            &RemovedComment {
                                kind: &found.kind,
                                value: &found.value,
                                author: found.author_id,
                                comment: &found.comment,
                                created_by: &found.created_by,
                                created_at: found.created_at,
                                edited_at: found.edited_at,
                            },
                        )?;
                        Ok(Audited::changed((), change))
                    })
                },
            )
            .await
    }
}
