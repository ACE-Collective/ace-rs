//! What SVS makes of an alert, on its page (PLAN.md 7.10 batch 7b): ace3's SVS banner
//! (`analysis/alert.html`'s `svs_banner`, filled from `saq/svs/alert_status.py`'s `alert_svs_view`).
//!
//! The alert page has the banner when SVS touched the alert, or the core gave its root a tag
//! (`analysis.roots.tags`: SVS's `svs_test`, `svs:marker_mismatch` and `svs:maintenance`). It says the
//! alert's status in words (test, test?, partial or mismatch), lists the test runs its attributions hold
//! to, each a link to the run's page for a viewer who holds `svs:run_read`, the markers that don't agree
//! with their run, and the root's tags. For a viewer holding `alert:write`, an alert a run holds has the
//! form that gives it back to analysts: disassociate it from every run that holds it, or, for one held by
//! context alone, mark it not a test, either with why. Both post to `/alerts/{id}/svs`, through
//! `Service::release_alert_from_svs`, which checks `alert:write` again and audits it, and come back to
//! the alert. Keeping an alert, or associating one with a run, is the run page's (`crate::svs`).
//!
//! The alert list says the same in a word beside each alert's description, with the root's tags
//! (`crate::list`).
//!
//! Everything here that came from an alert or a catalog (a test's name, a marker, a tag) is escaped by
//! askama; a run is linked by its uuid.

use ace_service::{ALERT_WRITE, AlertSvsView, SVS_RUN_READ, ServiceError, SvsStatus};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use uuid::Uuid;

use crate::Gui;
use crate::list::{one, pairs};
use crate::session::{Failure, SignedIn, see_other};

/// What a status means, for the banner and the list's title.
pub fn status_meaning(status: SvsStatus) -> &'static str {
    match status {
        SvsStatus::Test => {
            "A test alert: every detection is attributed to an SVS test run, at least one by its marker."
        }
        SvsStatus::TestContext => {
            "Probably a test alert: every detection is attributed to an SVS test run by its host and time alone. Keep it or mark it not a test."
        }
        SvsStatus::Partial => {
            "Some of its detections are attributed to an SVS test run, and some aren't: it stays with analysts."
        }
        SvsStatus::Mismatch => {
            "It holds an SVS test marker that doesn't agree with its run: it stays with analysts."
        }
    }
}

/// A run in the banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerRun {
    /// Its page, for a viewer who may open it.
    pub href: Option<String>,
    pub uuid: String,
    pub state: &'static str,
    /// The test's name, or its guid when the catalog no longer has it.
    pub test: String,
}

/// A marker that doesn't agree with its run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerMismatch {
    pub marker: String,
    pub result: String,
    pub run: Option<BannerRun>,
}

/// The alert page's SVS banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvsBanner {
    pub alert: Uuid,
    /// `test`, `test?`, `partial` or `mismatch`; empty when only a tag brought the banner.
    pub status: &'static str,
    pub meaning: &'static str,
    pub runs: Vec<BannerRun>,
    pub mismatches: Vec<BannerMismatch>,
    /// The root's tags.
    pub tags: Vec<String>,
    /// The viewer may give the alert back: the disassociate form.
    pub release: bool,
    /// And it is held by context alone: the not-a-test button.
    pub not_a_test: bool,
}

impl SvsBanner {
    /// The banner of an alert, or None when SVS never touched it and its root has no tag. `runs_open`
    /// is whether the viewer holds `svs:run_read`, and `can_write` `alert:write`.
    pub fn new(
        alert: Uuid,
        view: Option<&AlertSvsView>,
        tags: &[String],
        runs_open: bool,
        can_write: bool,
    ) -> Option<Self> {
        if view.is_none() && tags.is_empty() {
            return None;
        }
        let run = |run: &ace_service::RunRef| BannerRun {
            href: runs_open.then(|| crate::svs::run_href(run.uuid)),
            uuid: run.uuid.to_string(),
            state: run.state.as_str(),
            test: run
                .test_name
                .clone()
                .unwrap_or_else(|| run.test_guid.to_string()),
        };
        let runs: Vec<BannerRun> = view
            .map(|view| view.runs.iter().map(run).collect())
            .unwrap_or_default();
        let status = view.map(|view| view.status);
        Some(SvsBanner {
            alert,
            status: status.map_or("", SvsStatus::as_str),
            meaning: status.map_or("", status_meaning),
            mismatches: view
                .map(|view| {
                    view.mismatches
                        .iter()
                        .map(|mismatch| BannerMismatch {
                            marker: mismatch.marker.clone(),
                            result: mismatch.result.clone(),
                            run: mismatch.run.as_ref().map(run),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            tags: tags.to_vec(),
            release: can_write && !runs.is_empty(),
            not_a_test: can_write && status == Some(SvsStatus::TestContext),
            runs,
        })
    }
}

/// The banner of an alert for its page, read under `alert:read`.
pub(crate) async fn read(
    gui: &Gui,
    viewer: &SignedIn,
    alert: Uuid,
    tags: &[String],
) -> Result<Option<SvsBanner>, ServiceError> {
    let actor = &viewer.actor;
    let view = gui.service.alert_svs_view(actor, alert).await?;
    if view.is_none() && tags.is_empty() {
        return Ok(None);
    }
    let runs_open = gui.service.allowed(actor, &SVS_RUN_READ).await?;
    let can_write = gui.service.allowed(actor, &ALERT_WRITE).await?;
    Ok(SvsBanner::new(
        alert,
        view.as_ref(),
        tags,
        runs_open,
        can_write,
    ))
}

/// `POST /alerts/{id}/svs`: gives the alert back to analysts. `action` is `disassociate`, from every run
/// that holds it, with `reason`, or `not_a_test`, for an alert held by context alone.
pub(crate) async fn release(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
    body: Bytes,
) -> Response {
    let Ok(alert) = raw.parse::<Uuid>() else {
        return Failure::new(StatusCode::NOT_FOUND, "There's no such alert.", &parts)
            .into_response();
    };
    let form = pairs(&body);
    let not_a_test = match one(&form, "action") {
        Some("disassociate") => false,
        Some("not_a_test") => true,
        _ => {
            return Failure::new(
                StatusCode::BAD_REQUEST,
                "An action is disassociate or not_a_test.",
                &parts,
            )
            .into_response();
        }
    };
    // Not a test keeps its reason too: in each run's event and the audit row, while the attribution's
    // own removal reason stays ace3's fixed `not a test`
    let reason = one(&form, "reason")
        .map(str::trim)
        .filter(|reason| !reason.is_empty());
    match gui
        .service
        .release_alert_from_svs(&viewer.actor, alert, reason, not_a_test, Utc::now())
        .await
    {
        Ok(_) => see_other(&format!("/alerts/{alert}#svs"), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
