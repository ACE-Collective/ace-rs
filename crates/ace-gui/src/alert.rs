//! The alert view (PLAN.md 5.8): ace3's `analysis/index.html` and `alert.html`, its analysis tree, and the
//! stream that draws a result on an open page when it lands.
//!
//! `GET /alerts/{id}` reads the alert's tree through `Service::alert_tree`, its observables' comments
//! through `Service::alert_observable_comments` and the viewer's `alert_sections`, each under
//! `alert:read`, and draws them. `tree_view` turns a tree into what the template draws, as ace3's
//! `TreeNode` walk does: the observables the submission added at the top, under each observable its
//! modules' results, under each result the observables it added, and so on down. An observable is drawn
//! in full where the walk first meets it, and anywhere else as itself with a link to that place (ace3's
//! "Jump To Analysis"), so a loop ends. The walk keeps its own stack, so a deep tree can't overflow one.
//! An observable's type reads as ace3's `display_type` does, a module's label such as `Source IP (ip)`
//! first (`AlertObservable::display_label`).
//!
//! `GET /alerts/{id}/live` is a Datastar server-sent event stream. The page starts it with `data-init`.
//! When a result lands, `Service::watch_alert` wakes it, and it reads the tree again and sends it as a
//! `datastar-patch-elements` event, which Datastar morphs into `#alert-tree`. What it sends is the same
//! fragment the page drew, so a reload and a push can't disagree. Each event's id is a hash of the
//! fragment, and the page's own hash is in the stream's URL, so a stream that opens or reopens after a
//! landing sends the tree only if it changed, and one that doesn't is quiet.
//!
//! Its bounds:
//! - A stream reads and draws one tree at a time, and draws the next only once the last is written, since
//!   the body is pulled: a client that reads slowly holds one tree in memory, not a queue of them. A burst
//!   of landings is one wakeup (`ace-service`'s `alert_view`), and two reads of the tree are at least
//!   `MIN_REDRAW` apart.
//! - At most `LiveLimits::streams` are open at once, and `LiveLimits::per_user` for one user. Past
//!   either, the stream answers 503 and the page stays as it was drawn, still correct but not live.
//! - Every `LiveLimits::heartbeat` the stream sends a comment and checks the session again with the
//!   cookie it opened with, so it ends within one heartbeat of a logout, an expiry, a password change or
//!   a disable. A draw checks `alert:read` again, so it ends when that goes too.
//! - It spawns nothing. When the client goes, the server drops the stream and with it the watch, and
//!   the listener stops once nothing watches. A client that stays connected and stops reading isn't
//!   noticed until the socket's buffers fill and a write blocks; the two limits bound how many of those
//!   there can be.
//!
//! Escaping: every string from an alert, its modules or its comments goes through askama's escaper
//! (`templates`). The `data-init` expression holds only the alert's uuid and a hex hash, which can't
//! hold a quote. The page has no inline script or style, so it keeps 5.7's policy.
//!
//! A result's summary links to its page, `GET /alerts/{id}/results/{result}` (5.9), which draws it with its
//! type's view (`crate::analysis`) and lists the observables it added, as ace3's analysis page does.
//!
//! The page links to the alert's relationship graph, `GET /alerts/{id}/graph` (5.13, `GraphPage`), ace3's
//! vis.js network of the alert, drawn in the browser from the JSON API's
//! `/api/alerts/v1/alerts/{id}/graph` (`ace_service::graph_of`). ace3 drew it in a floating panel from a
//! button, which ace3 had commented out before removing vis.js (`ace3` commit `9f63a496`); here it's a
//! page of its own, so vis's 1.4 MB loads only where it's drawn. What differs: a click on a node selects
//! it and does nothing more, where ace3's swapped its label for its details and opened an analysis's page
//! in a new window; and relationships are edges, which ace3's graph didn't draw.
//!
//! From ace3, and what differs: the section ids, the tree's shape and the jump links are ace3's. Not here
//! yet: observable actions (#1032), the pruned
//! "Critical Analysis Overview", tag levels and colours, pivot links, summary details, and the other
//! sections of ace3's page, which come with what they show. A section opens and closes with `<details>`,
//! with no script, and its pin is a form that posts to `/preferences/alert-section`, which comes back
//! here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::time::Duration;

use ace_service::{
    Actor, AlertObservable, AlertTree, AlertWatch, ModuleResult, ObservableComment, RequestParts,
    ServiceError, Transport,
};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::Gui;
use crate::actions::{ActionLink, ObservableActions};
use crate::analysis::{DrawnView, Views};
use crate::places::{Place, Places};
use crate::session::{Failure, SignedIn, render};
use crate::templates::Layout;

/// The shortest time between two draws a stream sends, so a burst of landings is drawn once.
const MIN_REDRAW: Duration = Duration::from_millis(250);

/// The sections this page has, ace3's ids, and whether each starts open for an analyst who hasn't
/// chosen.
pub const SECTIONS: &[(&str, &str, bool)] = &[("alert_details", "Alert Details", true)];

/// How many live streams may be open, and how often each checks its session.
#[derive(Debug, Clone, Copy)]
pub struct LiveLimits {
    /// The most streams open at once.
    pub streams: usize,
    /// The most one user may have open.
    pub per_user: usize,
    pub heartbeat: Duration,
}

impl Default for LiveLimits {
    fn default() -> Self {
        LiveLimits {
            streams: 256,
            per_user: 16,
            heartbeat: Duration::from_secs(15),
        }
    }
}

/// The open streams, counted.
#[derive(Debug)]
pub(crate) struct Live {
    limits: LiveLimits,
    places: Places,
}

impl Live {
    pub(crate) fn new(limits: LiveLimits) -> Self {
        Live {
            limits,
            places: Places::new(limits.streams, limits.per_user),
        }
    }

    /// A place for one more stream of this actor's, or None past a limit.
    fn admit(&self, actor: &Actor) -> Option<Place> {
        self.places.admit(actor)
    }

    /// How many streams are open, for a test to see that a closed page leaves none.
    pub(crate) fn open(&self) -> usize {
        self.places.held()
    }
}

/// A comment on an observable, as the tree shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentView {
    pub author: String,
    pub text: String,
    pub when: String,
}

/// An observable where the tree shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservableNode {
    /// `o<id>`, the anchor of its place in full, which a reference links to.
    pub anchor: String,
    /// Whether this is a reference to where it's drawn in full.
    pub reference: bool,
    /// Whether it has results, so a reference has somewhere to jump to.
    pub analyzed: bool,
    /// Its type as ace3's `display_type` reads.
    pub label: String,
    /// Its value, or for a file the path it was analyzed under.
    pub value: String,
    pub time: Option<String>,
    pub tags: Vec<String>,
    pub detections: Vec<String>,
    pub comments: Vec<CommentView>,
    /// Its observable actions (5.9), where it's drawn in full.
    pub actions: Vec<ActionLink>,
}

/// A module's result where the tree shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultNode {
    /// `r<id>`.
    pub anchor: String,
    pub module: String,
    /// Its summary, or the module's name when it has none, as ace3 shows the analysis itself.
    pub title: String,
    pub tags: Vec<String>,
    /// Its page (5.9), which holds only the alert's uuid and the result's id.
    pub href: String,
}

/// One step of drawing the tree: the template draws these in order, so it needs no recursion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeLine {
    /// Opens an item: `<li>` and the node.
    Observable(ObservableNode),
    Result(ResultNode),
    /// A reference's link to where it's drawn in full.
    Jump(String),
    /// `<ul>` below the item last opened.
    Children,
    EndChildren,
    EndItem,
}

/// The tree as the template draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeView {
    pub lines: Vec<TreeLine>,
    /// The alert had more observables than one tree holds.
    pub truncated: bool,
}

impl TreeView {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// What the walk visits next.
enum Step<'a> {
    Observable(i64),
    Result(&'a ModuleResult),
    Line(TreeLine),
}

/// The tree's lines, from a snapshot and the comments on its observables. This is the view function the
/// page and the stream both draw with, and a test calls with a fixture.
pub fn tree_view(
    tree: &AlertTree,
    comments: &[ObservableComment],
    actions: &ObservableActions,
) -> TreeView {
    let by_id: HashMap<i64, &AlertObservable> =
        tree.observables.iter().map(|o| (o.id, o)).collect();
    let mut added_by: HashMap<i64, Vec<i64>> = HashMap::new();
    let mut added: HashSet<i64> = HashSet::new();
    for addition in &tree.additions {
        let list = added_by.entry(addition.result).or_default();
        if !list.contains(&addition.observable) {
            list.push(addition.observable);
        }
        added.insert(addition.observable);
    }
    let mut comments_of: HashMap<(&str, &str), Vec<CommentView>> = HashMap::new();
    for comment in comments {
        comments_of
            .entry((comment.kind.as_str(), comment.value.as_str()))
            .or_default()
            .push(CommentView {
                author: comment
                    .author
                    .display_name
                    .clone()
                    .unwrap_or_else(|| comment.author.username.clone()),
                text: comment.comment.clone(),
                when: comment
                    .created_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            });
    }

    // The submission's observables, then any that no result added, then any the walk didn't reach,
    // such as one a result added to itself: each starts a walk at the top, so nothing is left out.
    // what an observable modifier rule's `ignore` took out of the tree isn't drawn, as in ace3
    let top: HashSet<i64> = tree.top.iter().copied().collect();
    let shown = || tree.observables.iter().filter(|o| !o.ignored);
    let starts = shown()
        .filter(|o| top.contains(&o.id))
        .chain(shown().filter(|o| !top.contains(&o.id) && !added.contains(&o.id)))
        .chain(shown())
        .map(|o| o.id);
    let context = Context {
        alert: tree.alert.summary.id,
        actions,
        by_id,
        added_by,
        comments_of,
    };
    let mut drawn: HashSet<i64> = HashSet::new();
    let mut lines = Vec::new();
    let mut stack: Vec<Step<'_>> = Vec::new();
    for start in starts {
        if drawn.contains(&start) {
            continue;
        }
        stack.push(Step::Observable(start));
        walk(&context, &mut stack, &mut drawn, &mut lines);
    }
    TreeView {
        lines,
        truncated: tree.truncated,
    }
}

/// What the walk reads: the alert, its actions, its observables by id, which result added which, and the
/// comments.
struct Context<'a> {
    alert: Uuid,
    actions: &'a ObservableActions,
    by_id: HashMap<i64, &'a AlertObservable>,
    added_by: HashMap<i64, Vec<i64>>,
    comments_of: HashMap<(&'a str, &'a str), Vec<CommentView>>,
}

/// Draws what's on the stack, and everything below it.
fn walk<'a>(
    context: &Context<'a>,
    stack: &mut Vec<Step<'a>>,
    drawn: &mut HashSet<i64>,
    lines: &mut Vec<TreeLine>,
) {
    let Context {
        alert,
        actions,
        by_id,
        added_by,
        comments_of,
    } = context;
    let alert = *alert;
    while let Some(step) = stack.pop() {
        match step {
            Step::Line(line) => lines.push(line),
            Step::Observable(id) => {
                // past MAX_TREE_OBSERVABLES, which the view says, or ignored
                let Some(observable) = by_id.get(&id).filter(|o| !o.ignored) else {
                    continue;
                };
                let reference = !drawn.insert(id);
                let mut node = observable_node(
                    observable,
                    reference,
                    comments_of
                        .get(&(observable.kind.as_str(), observable.value.as_str()))
                        .cloned()
                        .unwrap_or_default(),
                );
                if !reference {
                    node.actions = actions.links(alert, observable);
                }
                let anchor = node.anchor.clone();
                lines.push(TreeLine::Observable(node));
                if observable.results.is_empty() {
                    lines.push(TreeLine::EndItem);
                } else if reference {
                    lines.extend([
                        TreeLine::Children,
                        TreeLine::Jump(anchor),
                        TreeLine::EndChildren,
                        TreeLine::EndItem,
                    ]);
                } else {
                    lines.push(TreeLine::Children);
                    stack.push(Step::Line(TreeLine::EndItem));
                    stack.push(Step::Line(TreeLine::EndChildren));
                    stack.extend(observable.results.iter().rev().map(Step::Result));
                }
            }
            Step::Result(result) => {
                lines.push(TreeLine::Result(ResultNode {
                    anchor: format!("r{}", result.id),
                    module: result.module.clone(),
                    title: result
                        .summary
                        .clone()
                        .unwrap_or_else(|| result.module.clone()),
                    tags: result.tags.clone(),
                    href: result_href(alert, result.id),
                }));
                match added_by.get(&result.id) {
                    Some(children) if !children.is_empty() => {
                        lines.push(TreeLine::Children);
                        stack.push(Step::Line(TreeLine::EndItem));
                        stack.push(Step::Line(TreeLine::EndChildren));
                        stack.extend(children.iter().rev().map(|id| Step::Observable(*id)));
                    }
                    _ => lines.push(TreeLine::EndItem),
                }
            }
        }
    }
}

/// A result's page.
fn result_href(alert: Uuid, result: i64) -> String {
    format!("/alerts/{alert}/results/{result}")
}

fn observable_node(
    observable: &AlertObservable,
    reference: bool,
    comments: Vec<CommentView>,
) -> ObservableNode {
    let mut detections: Vec<String> = Vec::new();
    for detection in &observable.detections {
        if !detections.contains(&detection.description) {
            detections.push(detection.description.clone());
        }
    }
    ObservableNode {
        anchor: format!("o{}", observable.id),
        reference,
        analyzed: !observable.results.is_empty(),
        label: observable.display_label(),
        value: display_value(observable),
        time: observable
            .time
            .map(|time| time.format("%Y-%m-%d %H:%M:%S %z").to_string()),
        tags: observable.tags.clone(),
        detections,
        comments,
        actions: Vec::new(),
    }
}

/// The observable's value as ace3's `display_value` reads: a file's path in place of its sha256, and a
/// value an observable modifier rule set before either, with it in parentheses.
fn display_value(observable: &AlertObservable) -> String {
    let value = match observable.files.first() {
        Some(file) if observable.kind == "file" => file.path.clone(),
        _ => observable.value.clone(),
    };
    match &observable.display_value {
        Some(shown) => format!("{shown} ({value})"),
        None => value,
    }
}

/// An observable modifier rule that matched in the alert, as ace3's Observable Modifier Rules card
/// shows it (`app/templates/analysis/observable_modifier_rules.html`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifierRuleView {
    pub name: String,
    pub uuid: String,
    /// How many observables it matched.
    pub observables: usize,
    /// The actions it applied, in the order first seen.
    pub actions: String,
    /// The observables its `ignore` took out.
    pub ignored: Vec<IgnoredView>,
}

/// An observable a rule's `ignore` took out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredView {
    pub kind: String,
    pub value: String,
    /// Whether it left the tree, or only the results the rule named, so it's still drawn elsewhere.
    pub hidden: bool,
}

/// The rules that matched in the alert, those that ignored something first, then by name, as ace3's
/// `build_modifier_rule_matches`.
pub fn modifier_rules(tree: &AlertTree) -> Vec<ModifierRuleView> {
    use ace_results::types::tag::ObservableModifierAnalysis;

    let mut rules: Vec<ModifierRuleView> = Vec::new();
    for observable in &tree.observables {
        for result in observable
            .results
            .iter()
            .filter(|r| r.analysis_type == "observable_modifier_analysis")
        {
            let Ok(analysis) =
                serde_json::from_value::<ObservableModifierAnalysis>(result.details.clone())
            else {
                continue;
            };
            for matched in analysis.matched_rules {
                let at = match rules.iter().position(|r| r.uuid == matched.uuid) {
                    Some(at) => at,
                    None => {
                        rules.push(ModifierRuleView {
                            name: matched.name.clone(),
                            uuid: matched.uuid.clone(),
                            observables: 0,
                            actions: String::new(),
                            ignored: Vec::new(),
                        });
                        rules.len() - 1
                    }
                };
                let rule = &mut rules[at];
                rule.observables += 1;
                for action in matched.actions_applied.keys() {
                    if !rule.actions.split(", ").any(|a| a == action) {
                        if !rule.actions.is_empty() {
                            rule.actions.push_str(", ");
                        }
                        rule.actions.push_str(action);
                    }
                }
                if matched.actions_applied.contains_key("ignore") {
                    rule.ignored.push(IgnoredView {
                        kind: observable.kind.clone(),
                        value: display_value(observable),
                        hidden: observable.ignored,
                    });
                }
            }
        }
    }
    rules.sort_by_key(|r| (r.ignored.is_empty(), r.name.to_lowercase()));
    rules
}

/// The tree on its own: what the page includes and what the stream sends.
#[derive(Debug, Template)]
#[template(path = "alert_tree.html")]
pub struct AlertTreeFragment {
    pub tree: TreeView,
}

impl AlertTreeFragment {
    /// The fragment's HTML and its version, a hash of it.
    pub fn render_versioned(&self) -> Result<(String, String), askama::Error> {
        let html = self.render()?;
        let version = hex::encode(&Sha256::digest(html.as_bytes())[..8]);
        Ok((html, version))
    }
}

/// A section of the page, with whether it starts open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub id: &'static str,
    pub title: &'static str,
    pub open: bool,
}

/// One row of the alert's details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    pub name: &'static str,
    pub value: String,
}

/// `/alerts/{id}`.
#[derive(Debug, Template)]
#[template(path = "alert.html")]
pub struct AlertPage {
    pub layout: Layout,
    pub id: Uuid,
    pub title: String,
    pub details_section: Section,
    pub details: Vec<Detail>,
    /// The detections on the alert itself, such as a tag configured as alertable makes.
    pub root_detections: Vec<String>,
    /// The observable modifier rules that matched.
    pub modifier_rules: Vec<ModifierRuleView>,
    /// How many observables the rules' `ignore` took out, each counted once.
    pub ignored_count: usize,
    pub tree: TreeView,
    /// The tree's version, which the stream starts from.
    pub version: String,
}

impl AlertPage {
    /// The page for a tree, its comments, the binary's observable actions and the viewer's section
    /// choices.
    pub fn new(
        layout: Layout,
        tree: &AlertTree,
        comments: &[ObservableComment],
        actions: &ObservableActions,
        sections: &BTreeMap<String, bool>,
    ) -> Result<Self, askama::Error> {
        let view = tree_view(tree, comments, actions);
        let (_, version) = AlertTreeFragment { tree: view.clone() }.render_versioned()?;
        let summary = &tree.alert.summary;
        let section = |id: &'static str| {
            let (id, title, default) = SECTIONS
                .iter()
                .copied()
                .find(|(name, _, _)| *name == id)
                .expect("a section of this page");
            Section {
                id,
                title,
                open: sections.get(id).copied().unwrap_or(default),
            }
        };
        let time =
            |time: chrono::DateTime<chrono::Utc>| time.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let mut details = vec![
            Detail {
                name: "Alerted",
                value: time(summary.alerted_at),
            },
            Detail {
                name: "Event time",
                value: summary
                    .event_time
                    .map(time)
                    .map(|t| format!("{t} ({})", summary.event_time_source))
                    .unwrap_or_else(|| "none".to_owned()),
            },
            Detail {
                name: "Analysis mode",
                value: summary.analysis_mode.clone(),
            },
            Detail {
                name: "Analysis",
                value: format!("{:?}", summary.analysis).to_lowercase(),
            },
            Detail {
                name: "Disposition",
                value: summary
                    .disposition
                    .clone()
                    .unwrap_or_else(|| "OPEN".to_owned()),
            },
            Detail {
                name: "Observables",
                value: tree.alert.observables.to_string(),
            },
            Detail {
                name: "Detections",
                value: tree.alert.detections.to_string(),
            },
        ];
        if let Some(by) = &summary.submitted_by {
            details.push(Detail {
                name: "Submitted by",
                value: by.name.clone().unwrap_or_else(|| by.id.clone()),
            });
        }
        let mut root_detections: Vec<String> = Vec::new();
        for detection in &tree.root_detections {
            if !root_detections.contains(&detection.description) {
                root_detections.push(detection.description.clone());
            }
        }
        let modifier_rules = modifier_rules(tree);
        let ignored_count = modifier_rules
            .iter()
            .flat_map(|r| r.ignored.iter().map(|i| (&i.kind, &i.value)))
            .collect::<HashSet<_>>()
            .len();
        Ok(AlertPage {
            layout,
            id: summary.id,
            title: summary.title.clone(),
            details_section: section("alert_details"),
            details,
            root_detections,
            modifier_rules,
            ignored_count,
            tree: view,
            version,
        })
    }
}

fn alert_id(raw: &str, parts: &Parts) -> Result<Uuid, Failure> {
    raw.parse()
        .map_err(|_| Failure::new(StatusCode::NOT_FOUND, "There's no such alert.", parts))
}

/// `GET /alerts/{id}`.
pub(crate) async fn page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
) -> Response {
    let id = match alert_id(&raw, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    let actor = &viewer.actor;
    let tree = match gui.service.alert_tree(actor, id).await {
        Ok(tree) => tree,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let comments = match gui.service.alert_observable_comments(actor, id).await {
        Ok(comments) => comments,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let sections = gui.service.alert_sections(actor).await.unwrap_or_else(|error| {
        tracing::warn!(%actor, "reading alert_sections failed, so the page has the defaults: {error}");
        BTreeMap::new()
    });
    match AlertPage::new(viewer.layout, &tree, &comments, &gui.actions, &sections) {
        Ok(page) => render(&page),
        Err(error) => {
            tracing::error!("an alert page couldn't be drawn: {error}");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// An observable a result added, as the result's page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedObservable {
    /// Where the tree draws it in full.
    pub anchor: String,
    pub label: String,
    pub value: String,
    pub tags: Vec<String>,
}

/// `/alerts/{id}/results/{result}` (5.9): one module's result on one observable, drawn by its type's view
/// (`crate::analysis`), with the observables it added. It's ace3's analysis page for one analysis.
#[derive(Debug, Template)]
#[template(path = "result.html")]
pub struct ResultPage {
    pub layout: Layout,
    pub alert_id: Uuid,
    pub alert_title: String,
    pub observable_label: String,
    pub observable_value: String,
    pub title: String,
    pub module: String,
    pub analysis_type: String,
    pub schema_version: i32,
    pub created_at: String,
    pub tags: Vec<String>,
    pub view: DrawnView,
    pub added: Vec<AddedObservable>,
}

impl ResultPage {
    /// The page of the result with this id in a tree, drawn with `views`, or None when the tree has no
    /// such result.
    pub fn new(layout: Layout, tree: &AlertTree, id: i64, views: &Views) -> Option<Self> {
        let (observable, result) = tree.observables.iter().find_map(|observable| {
            observable
                .results
                .iter()
                .find(|result| result.id == id)
                .map(|result| (observable, result))
        })?;
        let by_id: HashMap<i64, &AlertObservable> =
            tree.observables.iter().map(|o| (o.id, o)).collect();
        let mut seen = HashSet::new();
        let added = tree
            .additions
            .iter()
            .filter(|addition| addition.result == id && seen.insert(addition.observable))
            .filter_map(|addition| by_id.get(&addition.observable))
            .map(|added| {
                let node = observable_node(added, false, Vec::new());
                AddedObservable {
                    anchor: node.anchor,
                    label: node.label,
                    value: node.value,
                    tags: node.tags,
                }
            })
            .collect();
        let node = observable_node(observable, false, Vec::new());
        Some(ResultPage {
            layout,
            alert_id: tree.alert.summary.id,
            alert_title: tree.alert.summary.title.clone(),
            observable_label: node.label,
            observable_value: node.value,
            title: result
                .summary
                .clone()
                .unwrap_or_else(|| result.module.clone()),
            module: result.module.clone(),
            analysis_type: result.analysis_type.clone(),
            schema_version: result.schema_version,
            created_at: result
                .created_at
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            tags: result.tags.clone(),
            view: views.draw(
                &result.analysis_type,
                result.schema_version,
                &result.details,
            ),
            added,
        })
    }
}

/// `GET /alerts/{id}/results/{result}`. It reads the alert's tree under `alert:read`, as the alert's page
/// does, so a result is found only in an alert the viewer may read.
pub(crate) async fn result_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((raw, result)): Path<(String, String)>,
) -> Response {
    let id = match alert_id(&raw, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    let missing = || Failure::new(StatusCode::NOT_FOUND, "There's no such result.", &parts);
    let Ok(result) = result.parse::<i64>() else {
        return missing().into_response();
    };
    let tree = match gui.service.alert_tree(&viewer.actor, id).await {
        Ok(tree) => tree,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    match ResultPage::new(viewer.layout, &tree, result, &gui.views) {
        Some(page) => render(&page),
        None => missing().into_response(),
    }
}

/// `/alerts/{id}/graph` (5.13): the alert's relationship graph, ace3's vis.js network. The page holds the
/// alert's title and an empty `#graph` naming the JSON API's graph route; `static/graph.js` fetches it and
/// draws it with vis.js, both of which the base layout loads with the response's nonce (`Layout::scripts`),
/// so the page has no inline script. vis paints each label on a canvas as text, so nothing an alert holds
/// becomes markup.
#[derive(Debug, Template)]
#[template(path = "alert_graph.html")]
pub struct GraphPage {
    pub layout: Layout,
    pub id: Uuid,
    pub title: String,
    /// The graph's JSON, `/api/alerts/v1/alerts/{id}/graph`.
    pub source: String,
}

impl GraphPage {
    pub fn new(mut layout: Layout, alert: &ace_service::Alert) -> Self {
        let id = alert.summary.id;
        layout.scripts = vec![crate::assets::VIS.url(), crate::assets::GRAPH_SCRIPT.url()];
        GraphPage {
            layout,
            id,
            title: alert.summary.title.clone(),
            source: format!("/api/alerts/v1/alerts/{id}/graph"),
        }
    }
}

/// `GET /alerts/{id}/graph`. It reads the alert under `alert:read`, so the page is refused as its JSON
/// would be.
pub(crate) async fn graph_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
) -> Response {
    let id = match alert_id(&raw, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    match gui.service.alert(&viewer.actor, id).await {
        Ok(alert) => render(&GraphPage::new(viewer.layout, &alert)),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// What a stream needs to check its session again: the headers it opened with.
struct Credentials {
    transport: Transport,
    cookie: Option<String>,
    host: Option<String>,
}

impl Credentials {
    fn from(headers: &HeaderMap, transport: Transport) -> Self {
        let text = |name: header::HeaderName| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        Credentials {
            transport,
            cookie: text(header::COOKIE),
            host: text(header::HOST),
        }
    }

    fn parts(&self) -> RequestParts<'_> {
        RequestParts {
            transport: self.transport,
            method: "GET",
            authorization: None,
            cookie: self.cookie.as_deref(),
            sec_fetch_site: None,
            origin: None,
            host: self.host.as_deref(),
        }
    }
}

/// A stream's state between events.
struct Streaming {
    gui: Gui,
    actor: Actor,
    credentials: Credentials,
    watch: AlertWatch,
    /// The version the client has.
    version: String,
    /// Whether to read the tree before waiting: at the start, since a result may have landed between
    /// the page's read and the watch.
    dirty: bool,
    /// When it last read the tree, so the next read waits out `MIN_REDRAW`.
    drawn_at: Option<tokio::time::Instant>,
    heartbeat: tokio::time::Interval,
    _admitted: Place,
}

/// What a stream does next.
enum Next {
    Draw,
    Beat,
}

impl Streaming {
    /// The next event, or None to end the stream.
    async fn next(mut self) -> Option<(Result<Event, Infallible>, Self)> {
        loop {
            let next = if self.dirty {
                Next::Draw
            } else {
                tokio::select! {
                    () = self.watch.changed() => Next::Draw,
                    _ = self.heartbeat.tick() => Next::Beat,
                }
            };
            match next {
                Next::Beat => {
                    match self
                        .gui
                        .service
                        .authenticate_request(&self.credentials.parts())
                        .await
                    {
                        Ok(actor) if actor == self.actor => {}
                        Ok(_) | Err(ServiceError::NotAuthenticated) => {
                            tracing::debug!(actor = %self.actor, "an alert stream's session ended");
                            return None;
                        }
                        Err(error) => {
                            tracing::warn!(actor = %self.actor, "an alert stream couldn't check its session: {error}");
                            return None;
                        }
                    }
                    return Some((Ok(Event::default().comment("heartbeat")), self));
                }
                Next::Draw => {
                    self.dirty = false;
                    if let Some(drawn_at) = self.drawn_at {
                        // landings meanwhile wake the watch once, and this read sees them all
                        tokio::time::sleep_until(drawn_at + MIN_REDRAW).await;
                    }
                    self.drawn_at = Some(tokio::time::Instant::now());
                    let root = self.watch.root();
                    let read = async {
                        let tree = self.gui.service.alert_tree(&self.actor, root).await?;
                        let comments = self
                            .gui
                            .service
                            .alert_observable_comments(&self.actor, root)
                            .await?;
                        Ok::<_, ServiceError>((tree, comments))
                    };
                    let (tree, comments) = match read.await {
                        Ok(read) => read,
                        Err(error) => {
                            tracing::info!(actor = %self.actor, %root, "an alert stream ends: {error}");
                            return None;
                        }
                    };
                    let fragment = AlertTreeFragment {
                        tree: tree_view(&tree, &comments, &self.gui.actions),
                    };
                    let (html, version) = match fragment.render_versioned() {
                        Ok(drawn) => drawn,
                        Err(error) => {
                            tracing::error!("an alert tree couldn't be drawn: {error}");
                            return None;
                        }
                    };
                    if version == self.version {
                        continue;
                    }
                    self.version = version;
                    let event = patch_elements(&html, &self.version);
                    return Some((Ok(event), self));
                }
            }
        }
    }
}

/// A `datastar-patch-elements` event that morphs the element of the fragment's id. Each line of the HTML
/// is a `data: elements` line; a carriage return can't be in one, so it's written as its entity, which
/// is the same text inside an element or an attribute.
fn patch_elements(html: &str, version: &str) -> Event {
    let data = html
        .replace('\r', "&#13;")
        .lines()
        .map(|line| format!("elements {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    Event::default()
        .event("datastar-patch-elements")
        .id(version)
        .data(data)
}

/// `GET /alerts/{id}/live`.
pub(crate) async fn live(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
) -> Response {
    let id = match alert_id(&raw, &parts) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    // A reconnect says what it last had; the page's own version is in the URL.
    let version = parts
        .headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            parts.uri.query().and_then(|query| {
                serde_urlencoded::from_str::<Vec<(String, String)>>(query)
                    .ok()?
                    .into_iter()
                    .find(|(name, _)| name == "v")
                    .map(|(_, value)| value)
            })
        })
        .unwrap_or_default();
    let Some(admitted) = gui.live.admit(&viewer.actor) else {
        tracing::warn!(actor = %viewer.actor, "an alert stream was refused: too many are open");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let watch = match gui.service.watch_alert(&viewer.actor, id).await {
        Ok(watch) => watch,
        Err(error) => {
            let status = match error {
                ServiceError::PermissionDenied { .. } => StatusCode::FORBIDDEN,
                ServiceError::NotFound(_) => StatusCode::NOT_FOUND,
                error => {
                    tracing::error!("an alert stream couldn't start: {error}");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            };
            return status.into_response();
        }
    };
    let mut heartbeat = tokio::time::interval(gui.live.limits.heartbeat);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // the first tick is now; the first heartbeat is one period on
    heartbeat.reset();
    let state = Streaming {
        credentials: Credentials::from(&parts.headers, gui.transport),
        gui,
        actor: viewer.actor,
        watch,
        version,
        dirty: true,
        drawn_at: None,
        heartbeat,
        _admitted: admitted,
    };
    Sse::new(stream::unfold(state, Streaming::next)).into_response()
}
