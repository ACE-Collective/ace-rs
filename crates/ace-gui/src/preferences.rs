//! The theme menu of the base layout, ace3's theme switcher. ace3's `ace.js` calls its API with the
//! choice; here the menu is a form that posts to `/preferences/theme`, which works without a script and
//! comes back to the page it was on. It writes through `Service::set_preference`, which audits it.

use ace_service::{PreferenceValue, Theme, ThemePreference};
use axum::Form;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::Gui;
use crate::session::{Failure, SignedIn, local_path, see_other};

#[derive(Debug, Deserialize)]
pub(crate) struct ThemeForm {
    mode: String,
    next: Option<String>,
}

/// `POST /preferences/theme`.
pub(crate) async fn set_theme(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    form: Result<Form<ThemeForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let Some(mode) = Theme::named(&form.mode) else {
        return Failure::new(StatusCode::BAD_REQUEST, "There's no such theme.", &parts)
            .into_response();
    };
    let value = PreferenceValue::Theme(ThemePreference { mode });
    if let Err(error) = gui.service.set_preference(&viewer.actor, &value).await {
        return Failure::from_service(error, &parts).into_response();
    }
    see_other(
        form.next.as_deref().and_then(local_path).unwrap_or("/"),
        None,
    )
}
