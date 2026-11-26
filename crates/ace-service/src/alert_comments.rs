//! Analysts' comments on an alert (PLAN.md 5.15): ace3's `Comment` model (its `comments` table), its
//! GUI's `add_comment` and `delete_comment`, its event page's `bulk_add_comment`, the comment its
//! `set_dispositions` adds with a disposition, and its API's `PATCH /alerts/{uuid}/comments/{id}`.
//!
//! As in ace3:
//! - Reading needs `alert:read`, as an alert's other reads do, and adding, editing and deleting need
//!   `alert:write`.
//! - A comment is a person's: its author is the user, or the owner of the API key that wrote it
//!   (`observable_comments::author_of`). A key with no owner, or one of ACE's components, has no user to
//!   be the author, and is refused with 403.
//! - Only the author edits or deletes a comment, with any of their credentials that holds `alert:write`.
//!   An admin can't either.
//! - A comment is stored with its line breaks normalized (`normalize_comment`), so an edit whose text
//!   normalizes to what's stored isn't a change: it has no audit row and doesn't mark the comment edited.
//! - One comment goes on many alerts at once, the alert list's and an event's bulk Add Comment, a row on
//!   each, in one transaction with one audit row.
//! - A delete removes the row. Its audit row keeps the whole comment.
//! - A change asks for the alert's search documents again (`ace_core::queue::index_again`), as ace3
//!   submits an index task, and the indexer makes a document of each comment (`ace_search::documents`).
//!
//! What differs:
//! - ace3 takes any text. A comment here holds 1 to `MAX_COMMENT_CHARS` characters with something
//!   besides whitespace and no NUL, as an observable comment does.
//! - ace3 adds a comment to any uuid it's given, an alert or not. Here an id that is no alert is left out
//!   and said (`AddedAlertComments::not_alerts`), and a write that names no alert is `NotFound`.
//! - ace3's delete takes the comment's id alone; here, as ace3's edit does, it takes the alert's too, and
//!   a comment on another alert is `NotFound`.
//! - ace3 rotates the alert's version with each change, so that its page's poll draws it again. ace-rs's
//!   alert page is drawn again after the analyst's own change, and the list's refresh reads the comments
//!   every time, so there's no version to rotate.
//! - A read gives an alert's latest `MAX_SHOWN_COMMENTS`, oldest first, where ace3 gives every one.
//! - The AI API's database role can't read the table (migration 0064), so the alerts it reads carry
//!   none, as ace3's AI export carries none.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use crate::actor::{Actor, UserId};
use crate::alerts::{RecordedActor, no_alert};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::observable_comments::{CommentAuthor, author_of, checked};
use crate::permission::{ALERT_READ, ALERT_WRITE};
use crate::{Service, ServiceError};

/// The most alerts one write comments on: twice the alert list's largest page.
pub const MAX_COMMENTED_ALERTS: usize = 1000;

/// The most comments a read gives of one alert: its latest.
pub const MAX_SHOWN_COMMENTS: i64 = 100;

/// A comment on an alert.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertComment {
    pub id: i64,
    pub alert: Uuid,
    /// The person it's by, as they're called now; None for a comment ACE itself wrote, which
    /// `created_by` names.
    pub author: Option<CommentAuthor>,
    /// The actor that wrote it: the author, one of their keys, or one of ACE's components.
    pub created_by: RecordedActor,
    pub comment: String,
    pub created_at: DateTime<Utc>,
    /// When the text last changed; None when it never has.
    pub edited_at: Option<DateTime<Utc>>,
}

impl AlertComment {
    /// Who it's by, as a page shows it: the author's display name, else their username, as ace3's
    /// `gui_display`; `ACE` for ACE's own, which ace3 writes as its automation user, `ace`.
    pub fn author_name(&self) -> String {
        match &self.author {
            Some(author) => author
                .display_name
                .clone()
                .unwrap_or_else(|| author.username.clone()),
            None => "ACE".to_owned(),
        }
    }

    /// Whether this actor may edit or delete it: its author, through any of their credentials.
    pub fn is_by(&self, actor: &Actor) -> bool {
        match (&self.author, author_of(actor)) {
            (Some(author), Ok(user)) => author.id == user,
            _ => false,
        }
    }
}

/// What a write of one comment to many alerts did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedAlertComments {
    /// Each alert it went on, with its comment's id, in the order they were named.
    pub added: Vec<(Uuid, i64)>,
    /// The ids named that are no alert, left out.
    pub not_alerts: Vec<Uuid>,
}

struct CommentRow {
    id: i64,
    root_id: Uuid,
    author_id: Option<Uuid>,
    username: Option<String>,
    display_name: Option<String>,
    created_by: Value,
    comment: String,
    created_at: DateTime<Utc>,
    edited_at: Option<DateTime<Utc>>,
}

impl CommentRow {
    fn into_comment(self) -> Result<AlertComment, ServiceError> {
        let created_by = RecordedActor::from_row(Some(self.created_by))?
            .ok_or_else(|| ServiceError::from(ace_core::DbError::Decode("no actor".to_owned())))?;
        let author = match (self.author_id, self.username) {
            (Some(id), Some(username)) => Some(CommentAuthor {
                id: UserId(id),
                username,
                display_name: self.display_name,
            }),
            _ => None,
        };
        Ok(AlertComment {
            id: self.id,
            alert: self.root_id,
            author,
            created_by,
            comment: self.comment,
            created_at: self.created_at,
            edited_at: self.edited_at,
        })
    }
}

/// The latest `MAX_SHOWN_COMMENTS` comments of each of these alerts, oldest first, in one query
/// whatever their number. An alert with none has no entry.
pub(crate) async fn comments_of(
    conn: &mut PgConnection,
    roots: &[Uuid],
) -> Result<HashMap<Uuid, Vec<AlertComment>>, ServiceError> {
    let mut found: HashMap<Uuid, Vec<AlertComment>> = HashMap::new();
    if roots.is_empty() {
        return Ok(found);
    }
    let rows = sqlx::query_as!(
        CommentRow,
        r#"SELECT c.id AS "id!", c.root_id AS "root_id!", c.author_id,
                  c.username, c.display_name, c.created_by AS "created_by!: Value",
                  c.comment AS "comment!", c.created_at AS "created_at!", c.edited_at
           FROM unnest($1::uuid[]) AS r (id)
           CROSS JOIN LATERAL (
               SELECT c.id, c.root_id, c.author_id, u.username::text AS username, u.display_name,
                      c.created_by, c.comment, c.created_at, c.edited_at
               FROM analysis.alert_comments c LEFT JOIN service.users u ON u.id = c.author_id
               WHERE c.root_id = r.id
               ORDER BY c.created_at DESC, c.id DESC
               LIMIT $2
           ) c
           ORDER BY c.root_id, c.created_at, c.id"#,
        roots,
        MAX_SHOWN_COMMENTS,
    )
    .fetch_all(&mut *conn)
    .await?;
    for row in rows {
        let comment = row.into_comment()?;
        found.entry(comment.alert).or_default().push(comment);
    }
    Ok(found)
}

/// Gives each alert its comments, `Some` even when it has none, since the read looked.
pub(crate) async fn with_comments(
    conn: &mut PgConnection,
    alerts: &mut [crate::AlertSummary],
) -> Result<(), ServiceError> {
    let ids: Vec<Uuid> = alerts.iter().map(|alert| alert.id).collect();
    let mut found = comments_of(conn, &ids).await?;
    for alert in alerts {
        alert.comments = Some(found.remove(&alert.id).unwrap_or_default());
    }
    Ok(())
}

/// Adds the comment, already `checked`, by `author` as `actor` wrote it, to those of `roots` that are
/// alerts, and asks for their search documents again. Returns each alert's new comment's id, in the
/// order of `roots`. The caller's write records it.
pub(crate) async fn insert_comments(
    conn: &mut PgConnection,
    author: Option<UserId>,
    actor: &Actor,
    roots: &[Uuid],
    comment: &str,
) -> Result<Vec<(Uuid, i64)>, ServiceError> {
    let rows = sqlx::query!(
        "INSERT INTO analysis.alert_comments (root_id, author_id, created_by, comment)
         SELECT r.id, $2, $3::jsonb, $4 FROM analysis.roots r
         WHERE r.id = ANY ($1) AND r.alerted_at IS NOT NULL
         ORDER BY r.id
         RETURNING id, root_id",
        roots,
        author.map(|author| author.0),
        Json(actor) as _,
        comment,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|error| {
        let missing = error
            .as_database_error()
            .is_some_and(|error| error.is_foreign_key_violation());
        match author {
            Some(author) if missing => ServiceError::NoUser(author.0),
            _ => error.into(),
        }
    })?;
    let ids: HashMap<Uuid, i64> = rows.into_iter().map(|row| (row.root_id, row.id)).collect();
    let added: Vec<(Uuid, i64)> = roots
        .iter()
        .filter_map(|root| ids.get(root).map(|id| (*root, *id)))
        .collect();
    let commented: Vec<Uuid> = added.iter().map(|(root, _)| *root).collect();
    ace_core::queue::index_again(conn, &commented).await?;
    Ok(added)
}

/// A comment as its audit row records it when it's added.
#[derive(Serialize)]
struct AddedComment<'a> {
    alerts: &'a [Uuid],
    author: Uuid,
    comment: &'a str,
}

impl Recorded for AddedComment<'_> {}

/// The ids an add named that are no alert.
#[derive(Serialize)]
struct NotAlerts<'a> {
    not_alerts: &'a [Uuid],
}

impl Recorded for NotAlerts<'_> {}

/// A deleted comment, whole, since its row is gone.
#[derive(Serialize)]
struct RemovedComment<'a> {
    alert: Uuid,
    author: Option<Uuid>,
    comment: &'a str,
    created_by: &'a RecordedActor,
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
struct CommentOn {
    alert: Uuid,
    author: Option<Uuid>,
}

impl Recorded for CommentOn {}

/// The comment on this alert, locked for this write's transaction.
async fn comment_on(
    conn: &mut PgConnection,
    root: Uuid,
    id: i64,
) -> Result<AlertComment, ServiceError> {
    sqlx::query_as!(
        CommentRow,
        r#"SELECT c.id, c.root_id, c.author_id, u.username::text AS "username?",
                  u.display_name AS "display_name?", c.created_by AS "created_by!: Value",
                  c.comment, c.created_at, c.edited_at
           FROM analysis.alert_comments c LEFT JOIN service.users u ON u.id = c.author_id
           WHERE c.id = $1 AND c.root_id = $2
           FOR UPDATE OF c"#,
        id,
        root,
    )
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| ServiceError::NotFound(format!("no comment {id} on alert {root}")))?
    .into_comment()
}

/// The comment, locked, refused unless the actor is its author.
async fn own_comment(
    conn: &mut PgConnection,
    actor: &Actor,
    root: Uuid,
    id: i64,
) -> Result<AlertComment, ServiceError> {
    let found = comment_on(conn, root, id).await?;
    if !found.is_by(actor) {
        return Err(ServiceError::Forbidden(
            "only a comment's author can change or delete it".to_owned(),
        ));
    }
    Ok(found)
}

impl Service {
    /// Whether this service's reads give alerts their comments: all but the AI API's, whose process
    /// reads as the database role `ace_rs_ai`, which can't read them (migration 0064).
    pub(crate) fn reads_comments(&self) -> bool {
        self.ai_surface().is_none()
    }

    /// The comments of these alerts, each alert's latest `MAX_SHOWN_COMMENTS` oldest first, for a page
    /// that lists alerts the list doesn't read, such as an event's. It needs `alert:read`.
    pub async fn alert_comments(
        &self,
        actor: &Actor,
        roots: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<AlertComment>>, ServiceError> {
        if roots.len() > MAX_COMMENTED_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "the comments of at most {MAX_COMMENTED_ALERTS} alerts are read at once"
            )));
        }
        self.gate
            .read(actor, "alert_comments", &ALERT_READ, &|tx| {
                Box::pin(async move { comments_of(tx.conn(), roots).await })
            })
            .await
    }

    /// Adds one comment to each of these alerts, as ace3's Add Comment does for the alerts ticked or the
    /// one open. It needs `alert:write`, and the actor has to be a person (the module's docs). An id that
    /// is no alert is left out and returned; none that is one is `NotFound`.
    pub async fn add_alert_comment(
        &self,
        actor: &Actor,
        roots: &[Uuid],
        comment: &str,
    ) -> Result<AddedAlertComments, ServiceError> {
        let mut seen = BTreeSet::new();
        let roots: Vec<Uuid> = roots.iter().copied().filter(|r| seen.insert(*r)).collect();
        if roots.is_empty() {
            return Err(ServiceError::InvalidRequest(
                "a comment goes on at least one alert".to_owned(),
            ));
        }
        if roots.len() > MAX_COMMENTED_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "a comment goes on at most {MAX_COMMENTED_ALERTS} alerts at once"
            )));
        }
        let comment = checked(comment)?;
        let (roots, comment) = (&roots, comment.as_str());
        self.gate
            .write(actor, "add_alert_comment", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let author = author_of(actor)?;
                    let added =
                        insert_comments(tx.conn(), Some(author), actor, roots, comment).await?;
                    let not_alerts: Vec<Uuid> = roots
                        .iter()
                        .filter(|root| !added.iter().any(|(added, _)| added == *root))
                        .copied()
                        .collect();
                    if added.is_empty() {
                        return Err(match roots.as_slice() {
                            [one] => no_alert(*one),
                            _ => ServiceError::NotFound("none of these is an alert".to_owned()),
                        });
                    }
                    let alerts: Vec<Uuid> = added.iter().map(|(root, _)| *root).collect();
                    let ids: Vec<i64> = added.iter().map(|(_, id)| *id).collect();
                    let mut change = Change::added(
                        Target::alert_comments(&ids),
                        &AddedComment {
                            alerts: &alerts,
                            author: author.0,
                            comment,
                        },
                    )?;
                    if !not_alerts.is_empty() {
                        change = change.details(&NotAlerts {
                            not_alerts: &not_alerts,
                        })?;
                    }
                    Ok(Audited::changed(
                        AddedAlertComments { added, not_alerts },
                        change,
                    ))
                })
            })
            .await
    }

    /// Replaces the text of a comment on this alert and marks it edited, ace3's
    /// `update_alert_comment`. It needs `alert:write`, and only the author may. Text that normalizes to
    /// the stored text changes nothing.
    pub async fn edit_alert_comment(
        &self,
        actor: &Actor,
        root: Uuid,
        id: i64,
        comment: &str,
    ) -> Result<AlertComment, ServiceError> {
        let comment = checked(comment)?;
        let comment = comment.as_str();
        self.gate
            .write(actor, "edit_alert_comment", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let found = own_comment(tx.conn(), actor, root, id).await?;
                    // stored comments are normalized, so text that normalizes to it is no change
                    if found.comment == comment {
                        return Ok(Audited::unchanged(found));
                    }
                    sqlx::query!(
                        "UPDATE analysis.alert_comments SET comment = $2, edited_at = now()
                         WHERE id = $1",
                        id,
                        comment,
                    )
                    .execute(tx.conn())
                    .await?;
                    ace_core::queue::index_again(tx.conn(), &[root]).await?;
                    let edited = comment_on(tx.conn(), root, id).await?;
                    let change = Change::updated(
                        Target::alert_comment(id),
                        &CommentText {
                            comment: &found.comment,
                        },
                        &CommentText { comment },
                    )?
                    .details(&CommentOn {
                        alert: root,
                        author: found.author.as_ref().map(|author| author.id.0),
                    })?;
                    Ok(Audited::changed(edited, change))
                })
            })
            .await
    }

    /// Deletes a comment on this alert, as ace3 does: the row goes, and its audit row keeps it. It needs
    /// `alert:write`, and only the author may.
    pub async fn delete_alert_comment(
        &self,
        actor: &Actor,
        root: Uuid,
        id: i64,
    ) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "delete_alert_comment", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let found = own_comment(tx.conn(), actor, root, id).await?;
                    sqlx::query!("DELETE FROM analysis.alert_comments WHERE id = $1", id)
                        .execute(tx.conn())
                        .await?;
                    ace_core::queue::index_again(tx.conn(), &[root]).await?;
                    let change = Change::removed(
                        Target::alert_comment(id),
                        &RemovedComment {
                            alert: root,
                            author: found.author.as_ref().map(|author| author.id.0),
                            comment: &found.comment,
                            created_by: &found.created_by,
                            created_at: found.created_at,
                            edited_at: found.edited_at,
                        },
                    )?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }
}
