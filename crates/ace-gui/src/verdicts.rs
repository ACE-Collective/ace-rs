//! An alert's detection verdicts on its page (PLAN.md 7.14): ace3's verdict chips
//! (`static/js/detection_verdicts.js`) and the confirm of its disposition dialog, as forms.
//!
//! The alert page lists the alert's detections, each with its verdict as ace3's badge says it ("TP ·
//! inherited"), what it's on, and who stored a verdict and when. On a TP alert, for a viewer holding
//! `alert:write`, each has ace3's menu as small forms: "Mark as noise (FP)", "Confirm as TP" and "Inherit
//! from the alert", which post to `/alerts/{id}/detections/{detection}/verdict`, and the list has "Confirm
//! the others as TP" when any is unconfirmed, which posts to `/alerts/{id}/detections/confirm`. Each goes
//! through the service (`ace_service`'s `detection_verdicts`), which checks `alert:write` again and audits
//! it, and comes back to the list. The session's same-origin check runs before either (`session`). On an
//! FP or unclassified alert, or one only ACE grades, the list says why instead, as ace3's chips do.
//!
//! From ace3, and what differs: ace3 fills its chips from the API with a script, beside each detection in
//! the tree; here the list is drawn with the page and needs no script. ace3's disposition dialog also lists
//! the detections of a multi-signature alert to mark as noise while setting a TP disposition; ace4's alert
//! page has no disposition dialog yet, so marking them is this list's, after the disposition. The list
//! shows the alert's first `MAX_DETECTIONS_PAGE` detections and says when there are more.

use ace_service::{ALERT_WRITE, DetectionPoint, DetectionPointFilter, MAX_DETECTIONS_PAGE};
use ace_service::{Verdict, VerdictSource};
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use crate::Gui;
use crate::session::{Failure, SignedIn, see_other};

/// One of a detection's verdict forms: the value it posts and its label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictAction {
    pub value: &'static str,
    pub label: &'static str,
}

const MARK_FP: VerdictAction = VerdictAction {
    value: "fp",
    label: "Mark as noise (FP)",
};
const CONFIRM_TP: VerdictAction = VerdictAction {
    value: "tp",
    label: "Confirm as TP",
};
const INHERIT: VerdictAction = VerdictAction {
    value: "inherit",
    label: "Inherit from the alert",
};

/// One detection as the list draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictRow {
    pub id: i64,
    pub description: String,
    /// What it's on: an observable's type and value, or the alert.
    pub on: String,
    /// ace3's badge, such as "TP · inherited", empty with no verdict.
    pub badge: String,
    /// `tp` or `fp`, for the badge's look.
    pub verdict: &'static str,
    /// What the source means, the badge's title.
    pub title: &'static str,
    /// Who stored a verdict and when, if one is stored.
    pub stored: Option<String>,
    pub actions: Vec<VerdictAction>,
}

/// An alert's detections with their verdicts, and what the viewer may do with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictsView {
    pub alert: Uuid,
    pub rows: Vec<VerdictRow>,
    /// Why the verdicts can't be changed here, when the alert's disposition is why.
    pub note: Option<String>,
    /// Whether the forms are drawn.
    pub editable: bool,
    /// How many are unconfirmed, which "Confirm the others as TP" confirms.
    pub unconfirmed: usize,
    /// Whether the alert has more detections than the list shows.
    pub more: bool,
}

fn source_label(source: VerdictSource) -> (&'static str, &'static str) {
    match source {
        VerdictSource::Explicit => ("explicit", "set by an analyst"),
        VerdictSource::InheritedSingle => ("inherited", "inherited from the alert's disposition"),
        VerdictSource::InheritedMulti => (
            "unconfirmed",
            "inherited from the alert's disposition, on an alert where several signatures fired; nobody has confirmed it",
        ),
    }
}

impl VerdictsView {
    /// The list of an alert's detections. `refusal` is why the viewer's verdicts aren't taken on this alert
    /// (`Service::verdict_refusal`), and `can_write` whether they hold `alert:write`.
    pub fn new(
        alert: Uuid,
        detections: &[DetectionPoint],
        refusal: Option<String>,
        can_write: bool,
        more: bool,
    ) -> Self {
        let editable = can_write && refusal.is_none();
        let rows = detections
            .iter()
            .map(|d| {
                let (badge, verdict, title) = match (d.verdict, d.verdict_source) {
                    (Some(verdict), Some(source)) => {
                        let (label, title) = source_label(source);
                        (
                            format!("{} · {label}", verdict.as_str().to_uppercase()),
                            verdict.as_str(),
                            title,
                        )
                    }
                    _ => (String::new(), "", ""),
                };
                let explicit =
                    |v| d.verdict == Some(v) && d.verdict_source == Some(VerdictSource::Explicit);
                let mut actions = Vec::new();
                if editable {
                    if !explicit(Verdict::Fp) {
                        actions.push(MARK_FP);
                    }
                    if !explicit(Verdict::Tp) {
                        actions.push(CONFIRM_TP);
                    }
                    if d.override_verdict.is_some() {
                        actions.push(INHERIT);
                    }
                }
                let stored = d.override_verdict.map(|stored| {
                    let by = d
                        .override_by
                        .as_ref()
                        .map(|by| by.name.clone().unwrap_or_else(|| by.id.clone()))
                        .unwrap_or_default();
                    let at = d
                        .override_set_at
                        .map(|at| at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_default();
                    format!("{} stored by {by} at {at}", stored.as_str().to_uppercase())
                });
                VerdictRow {
                    id: d.id,
                    description: d.description.clone(),
                    on: match &d.observable {
                        Some((_, kind, value)) => format!("{kind}: {value}"),
                        None => "the alert".to_owned(),
                    },
                    badge,
                    verdict,
                    title,
                    stored,
                    actions,
                }
            })
            .collect();
        let unconfirmed = detections
            .iter()
            .filter(|d| d.verdict_source == Some(VerdictSource::InheritedMulti))
            .count();
        VerdictsView {
            alert,
            rows,
            note: refusal,
            editable,
            unconfirmed,
            more,
        }
    }
}

/// The verdicts of an alert for its page, read under `alert:read`.
pub(crate) async fn read(
    gui: &Gui,
    viewer: &SignedIn,
    alert: Uuid,
    disposition: Option<&str>,
) -> Result<VerdictsView, ace_service::ServiceError> {
    let actor = &viewer.actor;
    let filter = DetectionPointFilter {
        alert: Some(alert),
        ..DetectionPointFilter::default()
    };
    let page = gui
        .service
        .detection_points(actor, &filter, Some(MAX_DETECTIONS_PAGE), None)
        .await?;
    let can_write = gui.service.allowed(actor, &ALERT_WRITE).await?;
    Ok(VerdictsView::new(
        alert,
        &page.detections,
        gui.service.verdict_refusal(actor, disposition),
        can_write,
        page.next.is_some(),
    ))
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerdictForm {
    verdict: String,
}

fn missing(parts: &Parts) -> Failure {
    Failure::new(StatusCode::NOT_FOUND, "There's no such detection.", parts)
}

/// `POST /alerts/{id}/detections/{detection}/verdict`: `fp` or `tp` stores that verdict
/// (`Service::set_detection_verdict`), `inherit` clears it (`Service::clear_detection_verdict`).
pub(crate) async fn set(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((raw, detection)): Path<(String, String)>,
    form: Result<Form<VerdictForm>, FormRejection>,
) -> Response {
    let (Ok(alert), Ok(detection)) = (raw.parse::<Uuid>(), detection.parse::<i64>()) else {
        return missing(&parts).into_response();
    };
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let actor = &viewer.actor;
    let done = match form.verdict.as_str() {
        "inherit" => {
            gui.service
                .clear_detection_verdict(actor, alert, detection)
                .await
        }
        other => match Verdict::parse(other) {
            Some(verdict) => {
                gui.service
                    .set_detection_verdict(actor, alert, detection, verdict)
                    .await
            }
            None => {
                return Failure::new(
                    StatusCode::BAD_REQUEST,
                    "A verdict is tp, fp or inherit.",
                    &parts,
                )
                .into_response();
            }
        },
    };
    match done {
        Ok(_) => see_other(&format!("/alerts/{alert}#detections"), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// `POST /alerts/{id}/detections/confirm`: confirms the alert's unconfirmed TPs
/// (`Service::confirm_detections`).
pub(crate) async fn confirm(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
) -> Response {
    let Ok(alert) = raw.parse::<Uuid>() else {
        return Failure::new(StatusCode::NOT_FOUND, "There's no such alert.", &parts)
            .into_response();
    };
    match gui.service.confirm_detections(&viewer.actor, alert).await {
        Ok(_) => see_other(&format!("/alerts/{alert}#detections"), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
