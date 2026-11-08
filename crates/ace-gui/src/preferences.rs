//! The theme menu of the base layout, ace3's theme switcher. ace3's `ace.js` calls its API with the
//! choice; here the menu is a form that posts to `/preferences/theme`, which works without a script and
//! comes back to the page it was on. It writes through `Service::set_preference`, which audits it.
//!
//! The alert page's section pins are ace3's `alert_sections.js`, as a form: it reads the stored choices,
//! sets the one section and stores them again, as that script does, so a pin in another tab since this
//! page loaded is kept.

use ace_service::{
    AlertSectionsPreference, PreferenceValue, Theme, ThemePreference, is_section_id,
};
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

#[derive(Debug, Deserialize)]
pub(crate) struct SectionForm {
    section: String,
    open: String,
    next: Option<String>,
}

/// `POST /preferences/alert-section`: whether one section of the alert page starts open.
pub(crate) async fn set_alert_section(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    form: Result<Form<SectionForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let open = match form.open.as_str() {
        "true" => true,
        "false" => false,
        _ => {
            return Failure::new(StatusCode::BAD_REQUEST, "open is true or false.", &parts)
                .into_response();
        }
    };
    if !is_section_id(&form.section) {
        return Failure::new(StatusCode::BAD_REQUEST, "There's no such section.", &parts)
            .into_response();
    }
    let mut sections = match gui.service.alert_sections(&viewer.actor).await {
        Ok(sections) => sections,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    sections.insert(form.section, open);
    let value = PreferenceValue::AlertSections(AlertSectionsPreference { sections });
    // the key's own check, so more sections than it holds is refused as a bad request
    let value = match value.key().parse(value.to_json()) {
        Ok(value) => value,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    if let Err(error) = gui.service.set_preference(&viewer.actor, &value).await {
        return Failure::from_service(error, &parts).into_response();
    }
    see_other(
        form.next.as_deref().and_then(local_path).unwrap_or("/"),
        None,
    )
}
