//! Observable actions (PLAN.md 5.9, the GUI half of #1032): what an analyst can do with an observable,
//! listed under it in the alert's tree.
//!
//! ace3's observable types import its GUI's action classes and register them, with their presenters,
//! when they're imported (`saq/analysis/presenter/observable_presenter.py`'s `register_observable_action`,
//! now called from `saq/gui/observable_presenters.py`), so every process that reads an observable loads
//! the GUI. Here an action is plain data in the GUI crate, and the list is `ObservableActions`, built
//! from the binary's list: the open-source actions are `ObservableActions::builtin`, and a site adds its
//! own through `ace_app::App::observable_action`, as it adds a module or an analysis view. Nothing
//! registers at import, and no observable type knows about the GUI.
//!
//! An action is a link: the GUI draws it as `<a href>`, so it needs no script, and what it does is the
//! page or the route it leads to, which checks its own permission. An action's `href` is built from the
//! alert's uuid, the observable's id, type and value, and is drawn only when it's a path on this site or
//! an `https://` URL, so a link can't be `javascript:`. A value in it has to be percent-encoded
//! (`encode`).
//!
//! The open-source actions are those whose routes exist: ace3's "Add Comment", on every observable, which
//! leads to the comment form (`comment_page`, `add_comment`), "Download File As ZIP", on a file,
//! which is the JSON API's download (5.5), and "Add Directive", on every observable, which leads to a form
//! of the directives an analyst may add (`directive_page`, `add_directives`, PLAN.md decision 31). ace3's
//! others wait for what they act on: marking an observable interesting, a detection's enable, disable and
//! expiry, tags, VirusTotal, the clicker searches, URL crawls, file collection, rendering and the hex and
//! text views.
//!
//! "Add Directive" has no single ace3 counterpart. ace3's alert page adds a directive through its Add
//! Observable modal, whose multiselect offers `GUI_DIRECTIVES` (`_add_observable_modal.html`), and for an
//! observable the alert has, adds the directives to it (`app/analysis/views/edit/observable.py`). Here the
//! menu of the observable itself leads to the same choice, the directives the binary lists with ace3's
//! descriptions, as boxes to tick, since several may be added at once as in ace3's multiselect. A
//! directive the observable has is shown ticked and can't be ticked off: ace3 has no way to remove one.

use ace_service::AlertObservable;
use askama::Template;
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use crate::Gui;
use crate::session::{Failure, SignedIn, local_path, render, see_other};
use crate::templates::Layout;

/// The observable an action is for.
#[derive(Debug, Clone, Copy)]
pub struct ActionTarget<'a> {
    pub alert: Uuid,
    /// Its id in the alert.
    pub observable: i64,
    /// Its type's name, such as `file`.
    pub kind: &'a str,
    pub value: &'a str,
    /// Whether it's a file with stored bytes.
    pub has_file: bool,
}

/// One action: its name, its label in the menu, and its link for an observable, or None when it isn't one
/// it applies to.
#[derive(Clone, Copy)]
pub struct ObservableAction {
    /// ace3's name for it, such as `add_comment`.
    pub name: &'static str,
    pub label: &'static str,
    href: fn(&ActionTarget<'_>) -> Option<String>,
}

impl std::fmt::Debug for ObservableAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservableAction")
            .field("name", &self.name)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl ObservableAction {
    pub const fn new(
        name: &'static str,
        label: &'static str,
        href: fn(&ActionTarget<'_>) -> Option<String>,
    ) -> Self {
        ObservableAction { name, label, href }
    }

    /// The action's link for an observable, if it applies and the link is one to draw.
    pub fn href(&self, target: &ActionTarget<'_>) -> Option<String> {
        (self.href)(target).filter(|href| drawable(href))
    }
}

/// Whether a link may be drawn: a path on this site, or an `https://` URL, either printable ASCII with
/// nothing an attribute or a browser would read differently.
fn drawable(href: &str) -> bool {
    let plain = href.len() <= 4096
        && href.bytes().all(|byte| byte.is_ascii_graphic())
        && !href.contains(['"', '\'', '<', '>', '\\', '`']);
    plain && (local_path(href).is_some() || href.starts_with("https://"))
}

/// A value percent-encoded for a URL's path or query: everything but letters, digits and `-._~`.
pub fn encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// ace3's "Add Comment": the comment form for the observable.
pub const ADD_COMMENT: ObservableAction =
    ObservableAction::new("add_comment", "Add Comment", |target| {
        Some(format!(
            "/alerts/{}/observables/{}/comment",
            target.alert, target.observable
        ))
    });

/// ace3's "Download File As ZIP": the JSON API's download of a file, zipped with ace3's password.
pub const DOWNLOAD_FILE_AS_ZIP: ObservableAction =
    ObservableAction::new("file_download_as_zip", "Download File As ZIP", |target| {
        (target.kind == "file" && target.has_file).then(|| {
            format!(
                "/api/alerts/v1/alerts/{}/observables/{}/file",
                target.alert, target.observable
            )
        })
    });

/// "Add Directive": the form of the directives an analyst may add to the observable (PLAN.md decision 31).
pub const ADD_DIRECTIVE: ObservableAction =
    ObservableAction::new("add_directive", "Add Directive", |target| {
        Some(format!(
            "/alerts/{}/observables/{}/directives",
            target.alert, target.observable
        ))
    });

/// The binary's actions, in the order the menu lists them.
#[derive(Debug, Clone)]
pub struct ObservableActions {
    actions: Vec<ObservableAction>,
}

impl Default for ObservableActions {
    fn default() -> Self {
        ObservableActions::builtin()
    }
}

/// An action's link as the tree draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionLink {
    pub name: &'static str,
    pub label: &'static str,
    pub href: String,
}

impl ObservableActions {
    pub fn empty() -> Self {
        ObservableActions {
            actions: Vec::new(),
        }
    }

    /// The open-source actions.
    pub fn builtin() -> Self {
        ObservableActions::empty()
            .with(DOWNLOAD_FILE_AS_ZIP)
            .with(ADD_COMMENT)
            .with(ADD_DIRECTIVE)
    }

    /// These actions and `action`, which takes the place of one with the same name.
    pub fn with(mut self, action: ObservableAction) -> Self {
        match self.actions.iter_mut().find(|a| a.name == action.name) {
            Some(existing) => *existing = action,
            None => self.actions.push(action),
        }
        self
    }

    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.actions.iter().map(|a| a.name)
    }

    /// The links of the actions that apply to an observable of an alert.
    pub fn links(&self, alert: Uuid, observable: &AlertObservable) -> Vec<ActionLink> {
        let target = ActionTarget {
            alert,
            observable: observable.id,
            kind: &observable.kind,
            value: &observable.value,
            has_file: !observable.files.is_empty(),
        };
        self.actions
            .iter()
            .filter_map(|action| {
                action.href(&target).map(|href| ActionLink {
                    name: action.name,
                    label: action.label,
                    href,
                })
            })
            .collect()
    }
}

// ---- Add Comment ----

/// `/alerts/{id}/observables/{observable}/comment`: ace3's comment modal, as a page.
#[derive(Debug, Template)]
#[template(path = "comment.html")]
pub struct CommentPage {
    pub layout: Layout,
    pub alert_id: Uuid,
    pub alert_title: String,
    pub observable_id: i64,
    pub label: String,
    pub value: String,
}

/// The alert and the observable of a comment's path, read under `alert:read`.
async fn comment_target(
    gui: &Gui,
    viewer: &SignedIn,
    parts: &Parts,
    raw: &str,
    observable: &str,
) -> Result<(Uuid, String, AlertObservable), Failure> {
    let missing = || Failure::new(StatusCode::NOT_FOUND, "There's no such observable.", parts);
    let id: Uuid = raw.parse().map_err(|_| missing())?;
    let observable: i64 = observable.parse().map_err(|_| missing())?;
    let tree = gui
        .service
        .alert_tree(&viewer.actor, id)
        .await
        .map_err(|error| Failure::from_service(error, parts))?;
    let title = tree.alert.summary.title.clone();
    let found = tree
        .observables
        .into_iter()
        .find(|o| o.id == observable)
        .ok_or_else(missing)?;
    Ok((id, title, found))
}

/// The largest comment form: `ace_service::MAX_COMMENT_CHARS` characters of up to 4 bytes, each byte
/// percent-encoded to 3.
pub(crate) const MAX_COMMENT_FORM_BYTES: usize = ace_service::MAX_COMMENT_CHARS * 4 * 3 + 1024;

/// `GET /alerts/{id}/observables/{observable}/comment`.
pub(crate) async fn comment_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((raw, observable)): Path<(String, String)>,
) -> Response {
    let (alert_id, alert_title, observable) =
        match comment_target(&gui, &viewer, &parts, &raw, &observable).await {
            Ok(target) => target,
            Err(failure) => return failure.into_response(),
        };
    render(&CommentPage {
        layout: viewer.layout,
        alert_id,
        alert_title,
        observable_id: observable.id,
        label: observable.display_label(),
        value: observable.value,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct CommentForm {
    comment: String,
}

/// `POST /alerts/{id}/observables/{observable}/comment`: comments on the observable through
/// `Service::add_observable_comment`, which needs `observable:write` and audits it, and goes back to
/// where the tree draws it. The session's same-origin check ran before this (`session`).
pub(crate) async fn add_comment(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((raw, observable)): Path<(String, String)>,
    form: Result<Form<CommentForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let (alert_id, _, observable) =
        match comment_target(&gui, &viewer, &parts, &raw, &observable).await {
            Ok(target) => target,
            Err(failure) => return failure.into_response(),
        };
    match gui
        .service
        .add_observable_comment(
            &viewer.actor,
            &observable.kind,
            &observable.value,
            &form.comment,
        )
        .await
    {
        Ok(_) => see_other(
            // the whole tree: the observable may not be on a branch that carries a detection
            &format!("/alerts/{alert_id}?tree=full#o{}", observable.id),
            None,
        ),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

// ---- Add Directive ----

/// One directive the form offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectiveChoice {
    pub name: &'static str,
    pub description: &'static str,
    /// The observable has it already, so the box is ticked and can't be ticked off.
    pub set: bool,
}

/// `/alerts/{id}/observables/{observable}/directives`: the directives an analyst may add to the observable,
/// as boxes to tick (the module's docs).
#[derive(Debug, Template)]
#[template(path = "directives.html")]
pub struct DirectivePage {
    pub layout: Layout,
    pub alert_id: Uuid,
    pub alert_title: String,
    pub observable_id: i64,
    pub label: String,
    pub value: String,
    pub choices: Vec<DirectiveChoice>,
    /// The observable's directives that the form doesn't offer, such as those only ACE adds.
    pub others: Vec<String>,
}

impl DirectivePage {
    /// Whether any box is left to tick.
    pub fn any_to_add(&self) -> bool {
        self.choices.iter().any(|choice| !choice.set)
    }
}

/// The page for an observable, from the binary's list.
pub fn directive_choices(
    directives: &ace_service::DirectiveList,
    observable: &AlertObservable,
) -> (Vec<DirectiveChoice>, Vec<String>) {
    let choices = directives
        .iter()
        .map(|directive| DirectiveChoice {
            name: directive.name,
            description: directive.description,
            set: observable.directives.iter().any(|d| d == directive.name),
        })
        .collect();
    let others = observable
        .directives
        .iter()
        .filter(|d| !directives.contains(d))
        .cloned()
        .collect();
    (choices, others)
}

/// `GET /alerts/{id}/observables/{observable}/directives`.
pub(crate) async fn directive_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((raw, observable)): Path<(String, String)>,
) -> Response {
    let (alert_id, alert_title, observable) =
        match comment_target(&gui, &viewer, &parts, &raw, &observable).await {
            Ok(target) => target,
            Err(failure) => return failure.into_response(),
        };
    let (choices, others) = directive_choices(gui.service.directives(), &observable);
    render(&DirectivePage {
        layout: viewer.layout,
        alert_id,
        alert_title,
        observable_id: observable.id,
        label: observable.display_label(),
        value: observable.value,
        choices,
        others,
    })
}

/// The largest directive form: every listed directive's name, percent-encoded, with room to spare.
pub(crate) const MAX_DIRECTIVE_FORM_BYTES: usize = 64 * 1024;

/// `POST /alerts/{id}/observables/{observable}/directives`: adds the ticked directives (each a `directive`
/// field) through `Service::add_directives`, which needs `observable:write`, refuses a directive the binary
/// doesn't list, audits it and analyzes the alert again, and goes back to the observable in the tree. The
/// session's same-origin check ran before this (`session`).
pub(crate) async fn add_directives(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((raw, observable)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let directives = crate::list::all(&crate::list::pairs(&body), "directive");
    if directives.is_empty() {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "Tick at least one directive.",
            &parts,
        )
        .into_response();
    }
    let missing = || Failure::new(StatusCode::NOT_FOUND, "There's no such observable.", &parts);
    let (Ok(alert_id), Ok(observable)) = (raw.parse::<Uuid>(), observable.parse::<i64>()) else {
        return missing().into_response();
    };
    match gui
        .service
        .add_directives(&viewer.actor, alert_id, observable, &directives)
        .await
    {
        Ok(_) => see_other(
            // the whole tree: the observable may not be on a branch that carries a detection
            &format!("/alerts/{alert_id}?tree=full#o{observable}"),
            None,
        ),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
