//! Comments on an alert (PLAN.md 5.15): ace3's `add_comment`, `delete_comment` and its event page's
//! `bulk_add_comment`, and its alert page's edit, which ace3's page sends to its API with a script.
//!
//! - `POST /alerts/{id}/comments` adds a comment to the alert open, from its page's Add Comment.
//! - `POST /alerts/{id}/comments/{comment}` is its author's Save of a comment, or with `delete` its
//!   Delete, both on the alert's page.
//! - `POST /alerts/comment` adds one comment to the alerts ticked on the alert list or an event's page,
//!   the bulk form's Add Comment, and goes back to `next`. An alert gone since it was ticked is said on a
//!   page of its own, where ace3 adds a comment to any uuid it's given.
//!
//! Each goes through `Service`'s `add_alert_comment`, `edit_alert_comment` and `delete_alert_comment`,
//! which check `alert:write`, the author and the text. Where ace3 flashes a message and redirects on a
//! refusal, this answers with the refusal's page and status.

use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::Gui;
use crate::list::{MAX_BULK, all, one, pairs};
use crate::session::{Failure, SignedIn, local_path, render, see_other};
use crate::templates::Layout;

/// The largest comment form: `MAX_BULK` ids and a comment of `MAX_COMMENT_CHARS` characters of up to
/// four bytes each, percent-encoded.
pub(crate) const MAX_COMMENT_FORM_BYTES: usize =
    crate::list::MAX_BULK_FORM_BYTES + ace_service::MAX_COMMENT_CHARS * 4 * 3 + 4096;

/// What a bulk Add Comment did when some of the ticked alerts weren't there to take it.
#[derive(Debug, Template)]
#[template(path = "commented.html")]
pub struct CommentedPage {
    pub layout: Layout,
    pub added: Vec<Uuid>,
    pub not_alerts: Vec<Uuid>,
    pub next: String,
}

fn alert_page(id: Uuid) -> String {
    format!("/alerts/{id}#comments")
}

/// `POST /alerts/{id}/comments`.
pub(crate) async fn add(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    let Some(id) = path.ok().and_then(|Path(raw)| raw.parse::<Uuid>().ok()) else {
        return Failure::new(StatusCode::NOT_FOUND, "There's no such alert.", &parts)
            .into_response();
    };
    let form = pairs(&body);
    match gui
        .service
        .add_alert_comment(&viewer.actor, &[id], one(&form, "comment").unwrap_or(""))
        .await
    {
        Ok(_) => see_other(&alert_page(id), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// `POST /alerts/{id}/comments/{comment}`: `comment`'s new text, or `delete`.
pub(crate) async fn change(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Bytes,
) -> Response {
    let Some((id, comment)) = path.ok().and_then(|Path((alert, comment))| {
        Some((alert.parse::<Uuid>().ok()?, comment.parse::<i64>().ok()?))
    }) else {
        return Failure::new(
            StatusCode::NOT_FOUND,
            "A comment is named by its alert's id and its own.",
            &parts,
        )
        .into_response();
    };
    let form = pairs(&body);
    let changed = if one(&form, "delete").is_some() {
        gui.service
            .delete_alert_comment(&viewer.actor, id, comment)
            .await
    } else {
        gui.service
            .edit_alert_comment(
                &viewer.actor,
                id,
                comment,
                one(&form, "comment").unwrap_or(""),
            )
            .await
            .map(|_| ())
    };
    match changed {
        Ok(()) => see_other(&alert_page(id), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// `POST /alerts/comment`: `alert` for each ticked alert, `comment` and `next`.
pub(crate) async fn bulk(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let next = one(&form, "next")
        .and_then(local_path)
        .unwrap_or("/")
        .to_owned();
    let raw = all(&form, "alert");
    if raw.is_empty() {
        return Failure::new(StatusCode::BAD_REQUEST, "No alerts were ticked.", &parts)
            .into_response();
    }
    if raw.len() > MAX_BULK {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            format!("At most {MAX_BULK} alerts are commented on at once."),
            &parts,
        )
        .into_response();
    }
    let Ok(ids) = raw
        .iter()
        .map(|id| id.parse::<Uuid>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "An alert is named by its id.",
            &parts,
        )
        .into_response();
    };
    match gui
        .service
        .add_alert_comment(&viewer.actor, &ids, one(&form, "comment").unwrap_or(""))
        .await
    {
        Ok(added) if added.not_alerts.is_empty() => see_other(&next, None),
        Ok(added) => render(&CommentedPage {
            layout: viewer.layout,
            added: added.added.iter().map(|(alert, _)| *alert).collect(),
            not_alerts: added.not_alerts,
            next,
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
