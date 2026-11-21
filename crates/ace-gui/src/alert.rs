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
//! How the page is laid out (the owner's UI direction of 2026-11-15: what decides the alert first, and
//! everything else reachable but out of the way):
//! - The top: the title; the disposition, owner, queue, when it alerted, its analysis state, its type
//!   and what SVS makes of it, as one line of facts; the forms that change them, for a viewer with
//!   `alert:write` (the disposition form posts to the list's `/alerts/disposition` with this one
//!   alert); what fired and on what, each detection once with its verdict, at most `MAX_FIRED`; and
//!   the summary the alert's type chose (`crate::analysis::summary`): a mailbox alert's email, a hunt
//!   alert's hunt, a site's own, or the default, the key observables: those the submission added and
//!   those that carry a detection, at most `MAX_KEY_OBSERVABLES`.
//! - Collapsed panels, each a `<details>` whose summary line says what it holds: what SVS makes of the
//!   alert (PLAN.md 7.10 batch 7b, `crate::svs_alert`), the detections with their verdicts and the
//!   forms that change them (PLAN.md 7.14, `crate::verdicts`), remediation's coverage of the alert
//!   for a viewer with `remediation:read`, the alert's details, and the observable modifier rules.
//!   Each has the viewer's pin (`SECTIONS`), which opens it on every alert they look at.
//! - The analysis tree, which starts at the branches that carry a detection (`TreeMode::Detections`):
//!   each observable with one, the result of the module that raised it, and what leads down to them
//!   from the top. `?tree=full` draws the whole tree, the page's first line of the tree links each to
//!   the other, and the `analysis_tree` pin makes the whole tree the viewer's default. A tree with no
//!   detection on an observable is drawn whole. Nothing is left out of the whole tree, and a link to
//!   an observable's place (a key observable, a comment's way back, a result's additions) goes to
//!   the whole tree. The stream's URL says which tree its page drew (`t=full`), and draws that one.
//!
//! The alert's type is its origin's `alert_type` (`AlertTree::alert_type`), what its submitter said:
//! the hunter's is its hunt's, and a mailbox root's is `mailbox`. The service reads the origin with
//! the tree, which is all the page needs to choose.
//!
//! Ownership (PLAN.md 7.17): the details say who owns the alert and since when, and a viewer with
//! `alert:write` has ace3's Take Ownership and Assign Ownership as forms that post to `/alerts/owner`
//! (`crate::list::bulk_owner`) and come back here; taking an alert another analyst owns asks first, on
//! the page that says who has it.
//!
//! The ownership-changed notice (the owner's decision of 2026-11-15): ace3's page asks the API for its
//! alert's owner every five seconds and opens "Alert Ownership Changed!", naming who took it, when the
//! owner isn't the one the page was drawn with (`check_alert_meta` in `saq_analysis.js`). Here the page's
//! own stream says it, so it costs no request and no connection of its own:
//! - The stream's URL says who owned the alert when the page was drawn, `o`, a uuid or nothing.
//! - A change of owner notifies the channel a landing result does (migration 0063's trigger, with the
//!   root's id and nothing about the owner), so the stream wakes as it does for a result, reads the tree
//!   again under `alert:read`, and finds the owner in it. It also reads once as it opens, so a change
//!   between the page's read and the stream isn't missed.
//! - When the alert has an owner who isn't the one the stream last knew of, it sends
//!   `OwnerNoticeFragment` as a `datastar-patch-elements` event, which Datastar morphs into the page's
//!   empty `#owner-notice`: who owns it now and since when, and a link that loads the page again. As in
//!   ace3, an alert that became nobody's says nothing, and the next owner is said once.
//! - Who may see it is who may open the stream: `watch_alert` and every read check `alert:read`, and a
//!   stream whose reader lost it ends without an event. The notification itself holds no name.
//! - It's bounded as the stream is (`LiveLimits`): no stream, no notice, and the page says who owned
//!   the alert when it was drawn; a write checks the owner again under the alert's lock either way.
//! - The owner's name is a person's text and goes through askama's escaper, as the page's does. The
//!   page has no script of its own for it.
//!
//! From ace3, and what differs: the section ids, the tree's shape and the jump links are ace3's, and
//! the tree's branches with a detection are its pruned "Critical Analysis Overview". ace3 chooses a
//! whole template by alert type; here the type chooses the summary block and the rest of the page is
//! the same for every alert. Not here yet: tag levels and colours, pivot links, summary details, and
//! the other sections of ace3's page, which come with what they show. A section opens and closes
//! with `<details>`, with no script, and its pin is a form that posts to
//! `/preferences/alert-section`, which comes back here.

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
use crate::analysis::summary::{DrawnSummary, Summaries, SummaryInput};
use crate::analysis::{DrawnView, Views};
use crate::places::{Place, Places};
use crate::session::{Failure, SignedIn, render};
use crate::templates::Layout;
use crate::verdicts::VerdictsView;

/// The shortest time between two draws a stream sends, so a burst of landings is drawn once.
const MIN_REDRAW: Duration = Duration::from_millis(250);

/// The sections this page has, ace3's ids, and whether each starts open for an analyst who hasn't
/// chosen.
pub const SECTIONS: &[(&str, &str, bool)] = &[
    ("svs", "SVS", false),
    ("detections", "Detection Verdicts", false),
    ("remediation", "Remediation", false),
    ("alert_details", "Alert Details", false),
    ("modifier_rules", "Observable Modifier Rules", false),
    (TREE_SECTION, "Full analysis tree", false),
];

/// The section whose pin says how the analysis tree starts: open is the whole tree, closed only the
/// branches that carry a detection.
pub const TREE_SECTION: &str = "analysis_tree";

/// The most detections the page's top lists before the rest fold into the verdicts panel.
pub const MAX_FIRED: usize = 6;
/// The most key observables the default summary lists.
pub const MAX_KEY_OBSERVABLES: usize = 8;

/// How much of the tree a page draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TreeMode {
    /// Every observable and result, ace3's tree.
    #[default]
    Full,
    /// Only the branches that carry a detection: an observable with one, the result that raised it,
    /// and what leads down to it from the top. A tree with no detection on any observable is drawn
    /// whole.
    Detections,
}

impl TreeMode {
    /// What a page's `tree` parameter or a stream's `t` asks for, if it names a mode.
    pub fn named(name: &str) -> Option<TreeMode> {
        match name {
            "full" => Some(TreeMode::Full),
            "detections" => Some(TreeMode::Detections),
            _ => None,
        }
    }
}

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
    /// A file's type, what the type step found in its bytes (PLAN.md decision 25): libmagic's
    /// description, and its mime type for the title. ace3 showed it as file_type's result.
    pub file_type: Option<(String, String)>,
    /// A file's role under that path, what its producer made it, such as `email.attachment`.
    pub role: Option<String>,
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
    /// Why its module said it failed (`ModuleResult::error`), whole, for the badge's title.
    pub error: Option<String>,
    /// The reason as the line shows it beside the badge, cut to `FAILURE_SHOWN` characters: only
    /// when the result has no summary, since a summary usually says why already, as in ace3.
    pub error_shown: Option<String>,
    /// For a result the analysis cache wrote in place of a task (`ModuleResult::cached_at`), when
    /// the module's run it was kept from ended, for the `cached` badge's title.
    pub cached: Option<String>,
    /// Its links out of ACE, beside it, as ace3 draws an analysis's pivot links (PLAN.md decision
    /// 32 part (b)).
    pub links: Vec<crate::icons::DrawnLink>,
}

/// A module whose task on the observable failed and left no result (`FailedModule`), where the tree
/// lists it under its observable, as ace3 lists `root.analysis_failures`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedNode {
    pub module: String,
    /// The task's error, whole, or what ace3 says when there is none.
    pub reason: String,
    /// The reason as the line shows it, cut to `FAILURE_SHOWN` characters.
    pub shown: String,
}

/// How much of a failure's reason a tree line shows, as ace3's `truncate(200)`. The whole reason is
/// the badge's title and, for a result, on its page.
const FAILURE_SHOWN: usize = 200;

/// What ace3 shows for a failure recorded without a reason.
const FAILED_WITHOUT_REASON: &str = "the analysis module failed";

/// When a cached result's run ended, as a result's page shows a time.
fn when_cached(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// `text` cut to `FAILURE_SHOWN` characters, with an ellipsis when it was longer.
fn failure_shown(text: &str) -> String {
    if text.chars().count() <= FAILURE_SHOWN {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(FAILURE_SHOWN - 1).collect();
    cut.push('\u{2026}');
    cut
}

/// One step of drawing the tree: the template draws these in order, so it needs no recursion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeLine {
    /// Opens an item: `<li>` and the node.
    Observable(ObservableNode),
    Result(ResultNode),
    /// A whole item: a module that failed on the observable above without a result.
    Failed(FailedNode),
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
    /// Whether this is the whole tree, or only its branches that carry a detection.
    pub full: bool,
    /// Whether the tree has such branches at all, so the other view differs from this one.
    pub prunable: bool,
    /// How many observables it draws in full, and how many the alert's tree holds.
    pub shown: usize,
    pub total: usize,
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
    // boxed: the walk pushes only the small lines, and an observable's line is large
    Line(Box<TreeLine>),
}

/// The tree's lines, from a snapshot and the comments on its observables. This is the view function the
/// page and the stream both draw with, and a test calls with a fixture.
pub fn tree_view(
    tree: &AlertTree,
    comments: &[ObservableComment],
    actions: &ObservableActions,
) -> TreeView {
    tree_view_in(tree, comments, actions, TreeMode::Full)
}

/// The observables and results of the branches that carry a detection: each observable with one, each
/// result of the module that raised one on its observable, and every result and observable on a way
/// down to them from the top. Empty sets when no observable carries one.
fn detection_branches(tree: &AlertTree) -> (HashSet<i64>, HashSet<i64>) {
    let mut owner_of: HashMap<i64, i64> = HashMap::new();
    let mut observables: HashSet<i64> = HashSet::new();
    let mut results: HashSet<i64> = HashSet::new();
    let mut queue: Vec<i64> = Vec::new();
    for observable in tree.observables.iter().filter(|o| !o.ignored) {
        for result in &observable.results {
            owner_of.insert(result.id, observable.id);
        }
        if observable.detections.is_empty() {
            continue;
        }
        observables.insert(observable.id);
        queue.push(observable.id);
        for result in &observable.results {
            let raised = observable
                .detections
                .iter()
                .any(|d| d.module.as_deref() == Some(result.module.as_str()));
            if raised {
                results.insert(result.id);
            }
        }
    }
    let mut added_in: HashMap<i64, Vec<i64>> = HashMap::new();
    for addition in &tree.additions {
        added_in
            .entry(addition.observable)
            .or_default()
            .push(addition.result);
    }
    // up from each: the results that added it, and the observables those are on
    while let Some(observable) = queue.pop() {
        for result in added_in.get(&observable).into_iter().flatten() {
            results.insert(*result);
            if let Some(owner) = owner_of.get(result)
                && observables.insert(*owner)
            {
                queue.push(*owner);
            }
        }
    }
    (observables, results)
}

/// The tree's lines in a mode: the whole tree, or its branches that carry a detection, with ace4's
/// own pivot link icons, which are none.
pub fn tree_view_in(
    tree: &AlertTree,
    comments: &[ObservableComment],
    actions: &ObservableActions,
    mode: TreeMode,
) -> TreeView {
    tree_view_drawn(
        tree,
        comments,
        actions,
        &crate::icons::PivotIcons::builtin(),
        mode,
    )
}

/// `tree_view_in`, with the binary's pivot link icons.
pub fn tree_view_drawn(
    tree: &AlertTree,
    comments: &[ObservableComment],
    actions: &ObservableActions,
    icons: &crate::icons::PivotIcons,
    mode: TreeMode,
) -> TreeView {
    let (kept_observables, kept_results) = detection_branches(tree);
    let prunable = !kept_observables.is_empty();
    let keep = (mode == TreeMode::Detections && prunable).then_some(Keep {
        observables: kept_observables,
        results: kept_results,
    });
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
    let total = shown().count();
    let full = keep.is_none();
    let context = Context {
        alert: tree.alert.summary.id,
        actions,
        icons,
        by_id,
        added_by,
        comments_of,
        keep,
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
        full,
        prunable,
        shown: drawn.len(),
        total,
    }
}

/// What a pruned walk draws: the observables and results of the branches that carry a detection.
struct Keep {
    observables: HashSet<i64>,
    results: HashSet<i64>,
}

/// What the walk reads: the alert, its actions, its observables by id, which result added which, and the
/// comments.
struct Context<'a> {
    alert: Uuid,
    actions: &'a ObservableActions,
    icons: &'a crate::icons::PivotIcons,
    by_id: HashMap<i64, &'a AlertObservable>,
    added_by: HashMap<i64, Vec<i64>>,
    comments_of: HashMap<(&'a str, &'a str), Vec<CommentView>>,
    /// None for the whole tree.
    keep: Option<Keep>,
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
        icons,
        by_id,
        added_by,
        comments_of,
        keep,
    } = context;
    let alert = *alert;
    let kept_observable = |id: i64| keep.as_ref().is_none_or(|k| k.observables.contains(&id));
    let kept_result = |id: i64| keep.as_ref().is_none_or(|k| k.results.contains(&id));
    while let Some(step) = stack.pop() {
        match step {
            Step::Line(line) => lines.push(*line),
            Step::Observable(id) => {
                // past MAX_TREE_OBSERVABLES, which the view says, or ignored
                let Some(observable) = by_id
                    .get(&id)
                    .filter(|o| !o.ignored && kept_observable(o.id))
                else {
                    continue;
                };
                let results: Vec<&ModuleResult> = observable
                    .results
                    .iter()
                    .filter(|result| kept_result(result.id))
                    .collect();
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
                // the modules that failed on it without a result, where it's drawn in full, before
                // its results, as ace3 lists them
                let failed: Vec<TreeLine> = if reference {
                    Vec::new()
                } else {
                    observable
                        .failed
                        .iter()
                        .flatten()
                        .map(|failed| {
                            let reason = failed
                                .error
                                .as_deref()
                                .filter(|error| !error.trim().is_empty())
                                .unwrap_or(FAILED_WITHOUT_REASON);
                            TreeLine::Failed(FailedNode {
                                module: failed.module.clone(),
                                reason: reason.to_owned(),
                                shown: failure_shown(reason),
                            })
                        })
                        .collect()
                };
                if results.is_empty() && failed.is_empty() {
                    lines.push(TreeLine::EndItem);
                } else if results.is_empty() {
                    lines.push(TreeLine::Children);
                    lines.extend(failed);
                    lines.extend([TreeLine::EndChildren, TreeLine::EndItem]);
                } else if reference {
                    lines.extend([
                        TreeLine::Children,
                        TreeLine::Jump(anchor),
                        TreeLine::EndChildren,
                        TreeLine::EndItem,
                    ]);
                } else {
                    lines.push(TreeLine::Children);
                    lines.extend(failed);
                    stack.push(Step::Line(Box::new(TreeLine::EndItem)));
                    stack.push(Step::Line(Box::new(TreeLine::EndChildren)));
                    stack.extend(results.into_iter().rev().map(Step::Result));
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
                    error: result.error.clone(),
                    error_shown: result
                        .error
                        .as_deref()
                        .filter(|_| result.summary.is_none())
                        .map(failure_shown),
                    cached: result.cached_at.map(when_cached),
                    links: crate::icons::DrawnLink::of(&result.pivot_links, icons),
                }));
                let children: Vec<i64> = added_by
                    .get(&result.id)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|id| by_id.get(id).is_some_and(|o| !o.ignored) && kept_observable(*id))
                    .collect();
                if children.is_empty() {
                    lines.push(TreeLine::EndItem);
                } else {
                    lines.push(TreeLine::Children);
                    stack.push(Step::Line(Box::new(TreeLine::EndItem)));
                    stack.push(Step::Line(Box::new(TreeLine::EndChildren)));
                    stack.extend(children.into_iter().rev().map(Step::Observable));
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
        file_type: observable
            .file_type
            .as_ref()
            .map(|t| (t.description.clone(), t.mime.clone())),
        role: observable.files.first().and_then(|f| f.role.clone()),
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

/// The ownership-changed notice (the module's docs): what the stream sends when the alert has an owner
/// the open page wasn't drawn with, ace3's "Alert Ownership Changed!" dialog. Datastar morphs it into
/// the page's `#owner-notice`.
#[derive(Debug, Template)]
#[template(path = "alert_owner_notice.html")]
pub struct OwnerNoticeFragment {
    pub alert: Uuid,
    /// What the new owner is called.
    pub owner: String,
    /// Since when, in UTC, when the alert says.
    pub since: Option<String>,
}

impl OwnerNoticeFragment {
    /// The notice for an alert as it was just read, or None when nobody owns it, or the owner is the
    /// one the page already knows of.
    pub fn of(summary: &ace_service::AlertSummary, known: Option<Uuid>) -> Option<Self> {
        let owner = summary.owner.as_ref()?;
        if Some(owner.id.0) == known {
            return None;
        }
        Some(OwnerNoticeFragment {
            alert: summary.id,
            owner: owner.name.clone(),
            since: summary
                .owned_at
                .map(|at| at.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        })
    }
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

/// One detection in the page's top: what fired and on what, with its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub description: String,
    /// What it's on: an observable's type and value, a file by its path, or the alert.
    pub on: String,
    /// The same as the verdicts name it, an observable's type and its stored value, which is how a
    /// verdict finds its detection here.
    pub key: String,
    /// How many more observables the same detection is on.
    pub others: usize,
    /// Its verdict's badge, such as `TP · inherited`, empty with none.
    pub badge: String,
    /// `tp` or `fp`, the badge's look.
    pub verdict: &'static str,
    /// What the badge's source means.
    pub title: &'static str,
}

/// One of the alert's key observables, which the default summary lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyObservable {
    pub label: String,
    pub value: String,
    /// The whole value when `value` was cut.
    pub full: Option<String>,
    /// Where the whole tree draws it.
    pub href: String,
    /// How many detections are on it.
    pub detections: usize,
    pub tags: Vec<String>,
}

/// The alert's remediation, as its panel shows it: ace3's remediation badge and its targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationPanel {
    pub badge: crate::remediation::CoverageBadge,
    /// Each target and what became of it, in ace3's words.
    pub targets: Vec<(String, String)>,
    pub more: usize,
    /// The page that finds the alert's targets, where one is removed or restored.
    pub href: String,
}

impl RemediationPanel {
    /// The panel of an alert's coverage, or None when there's nothing to show for it.
    pub fn of(alert: Uuid, coverage: &ace_service::Coverage) -> Option<Self> {
        let badge = crate::remediation::coverage_badge(coverage)?;
        Some(RemediationPanel {
            badge,
            targets: coverage
                .targets
                .iter()
                .take(MAX_KEY_OBSERVABLES)
                .map(|target| (target.recipient().to_owned(), target.status_display()))
                .collect(),
            more: coverage.targets.len().saturating_sub(MAX_KEY_OBSERVABLES),
            href: format!("/remediations/targets?alert={alert}"),
        })
    }
}

/// What a page is drawn with besides the alert: the binary's summaries, the site's dispositions, what
/// the viewer asked of the tree and what remediation did.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageOptions<'a> {
    /// The tree the page's `tree` parameter asked for; None follows the viewer's pin, and then the
    /// branches that carry a detection.
    pub tree: Option<TreeMode>,
    /// None draws with the open-source summaries.
    pub summaries: Option<&'a Summaries>,
    /// None draws a disposition as ace3's set does.
    pub dispositions: Option<&'a ace_service::Dispositions>,
    /// The alert's remediation coverage, when the viewer may read it.
    pub remediation: Option<&'a ace_service::Coverage>,
    /// None draws pivot links with ace4's own icons, which are none.
    pub icons: Option<&'a crate::icons::PivotIcons>,
}

/// `/alerts/{id}`.
#[derive(Debug, Template)]
#[template(path = "alert.html")]
pub struct AlertPage {
    pub layout: Layout,
    pub id: Uuid,
    pub title: String,
    /// The alert's disposition, `OPEN` for none, and its badge's class, the disposition's `css`.
    pub disposition: String,
    pub disposition_css: String,
    pub queue: String,
    /// Who owns it, and since when.
    pub owner_name: Option<String>,
    pub owned_since: Option<String>,
    pub alerted: String,
    /// `analyzing`, `complete` or `cancelled`.
    pub analysis: String,
    /// The alert's type, its origin's `alert_type`, which chooses the summary.
    pub alert_type: Option<String>,
    /// The tags the core gave the root.
    pub tags: Vec<String>,
    /// What fired and on what, at most `MAX_FIRED`, and how many more the verdicts panel lists.
    pub fired: Vec<Fired>,
    pub more_fired: usize,
    /// The alert's own links out of ACE, such as its hunt's, ace3's "External Link" rows (PLAN.md
    /// decision 32 part (b)); none draws no section.
    pub external_links: Vec<crate::icons::DrawnLink>,
    /// The summary of the alert's type, or None for the default: the key observables.
    pub summary: Option<DrawnSummary>,
    pub key_observables: Vec<KeyObservable>,
    pub more_observables: usize,
    pub svs_section: Section,
    pub verdicts_section: Section,
    pub remediation_section: Section,
    pub details_section: Section,
    pub rules_section: Section,
    /// Whether the viewer's pin starts the tree whole.
    pub tree_section: Section,
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
    /// Who owned the alert when the page was drawn, a uuid, or empty for nobody: what the stream's
    /// ownership-changed notice starts from.
    pub owner: String,
    /// The alert's detections with their verdicts (PLAN.md 7.14, `crate::verdicts`).
    pub verdicts: Option<VerdictsView>,
    /// What SVS makes of the alert, with its root's tags (PLAN.md 7.10, `crate::svs_alert`).
    pub svs: Option<crate::svs_alert::SvsBanner>,
    /// Take Ownership and Assign Ownership, for a viewer with `alert:write` (PLAN.md 7.17).
    pub ownership: Option<OwnershipForms>,
    /// The dispositions the page's form offers a viewer with `alert:write`: the site's an analyst may
    /// choose, in order. The form posts to the list's `/alerts/disposition` with this one alert.
    pub dispositions: Vec<String>,
    pub remediation: Option<RemediationPanel>,
}

/// ace3's Take Ownership and Assign Ownership buttons of the alert page (`analysis/index.html`): forms
/// that post to `/alerts/owner` (`crate::list::bulk_owner`) and come back here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipForms {
    /// The alert is the viewer's already, so there's nothing to take.
    pub mine: bool,
    /// Who Assign offers: the enabled users.
    pub users: Vec<crate::list::OwnerOption>,
}

/// What fired, from the tree alone: each detection once, on the first observable that carries it.
fn fired_of_tree(tree: &AlertTree) -> Vec<Fired> {
    let mut fired: Vec<Fired> = Vec::new();
    let mut add = |description: &str, on: String, key: String| match fired
        .iter_mut()
        .find(|f| f.description == description)
    {
        Some(known) => known.others += 1,
        None => fired.push(Fired {
            description: description.to_owned(),
            on,
            key,
            others: 0,
            badge: String::new(),
            verdict: "",
            title: "",
        }),
    };
    for detection in &tree.root_detections {
        add(
            &detection.description,
            "the alert".to_owned(),
            "the alert".to_owned(),
        );
    }
    for observable in tree.observables.iter().filter(|o| !o.ignored) {
        for detection in &observable.detections {
            add(
                &detection.description,
                format!("{}: {}", observable.kind, display_value(observable)),
                format!("{}: {}", observable.kind, observable.value),
            );
        }
    }
    fired
}

/// Gives each detection of the page's top the verdict of its row in the verdicts: the row with its
/// description on the same observable, or failing that the first with its description.
fn verdicts_onto(fired: &mut [Fired], verdicts: &VerdictsView) {
    for detection in fired {
        let rows = || {
            verdicts
                .rows
                .iter()
                .filter(|row| row.description == detection.description)
        };
        if let Some(row) = rows()
            .find(|row| row.on == detection.key)
            .or_else(|| rows().next())
        {
            detection.badge = row.badge.clone();
            detection.verdict = row.verdict;
            detection.title = row.title;
        }
    }
}

/// The default summary's observables: those the submission added, then those that carry a detection,
/// each once.
fn key_observables(tree: &AlertTree) -> (Vec<KeyObservable>, usize) {
    let top: HashSet<i64> = tree.top.iter().copied().collect();
    let shown = || tree.observables.iter().filter(|o| !o.ignored);
    let mut chosen: Vec<&AlertObservable> = shown().filter(|o| top.contains(&o.id)).collect();
    for observable in shown().filter(|o| !o.detections.is_empty()) {
        if !chosen.iter().any(|o| o.id == observable.id) {
            chosen.push(observable);
        }
    }
    // the ones with a detection first, in the order the tree has them
    chosen.sort_by_key(|o| o.detections.is_empty());
    let more = chosen.len().saturating_sub(MAX_KEY_OBSERVABLES);
    let alert = tree.alert.summary.id;
    let observables = chosen
        .into_iter()
        .take(MAX_KEY_OBSERVABLES)
        .map(|observable| {
            let value = display_value(observable);
            let cut = crate::analysis::clip(&value, MAX_KEY_VALUE);
            KeyObservable {
                label: observable.display_label(),
                full: (cut.more > 0).then(|| value.clone()),
                value: if cut.more > 0 {
                    format!("{}…", cut.text)
                } else {
                    cut.text
                },
                href: format!("/alerts/{alert}?tree=full#o{}", observable.id),
                detections: observable.detections.len(),
                tags: observable.tags.clone(),
            }
        })
        .collect();
    (observables, more)
}

/// The most bytes of a key observable's value the summary shows.
const MAX_KEY_VALUE: usize = 160;

impl AlertPage {
    /// The page for a tree, its comments, the binary's observable actions and the viewer's section
    /// choices, with the open-source summaries.
    pub fn new(
        layout: Layout,
        tree: &AlertTree,
        comments: &[ObservableComment],
        actions: &ObservableActions,
        sections: &BTreeMap<String, bool>,
    ) -> Result<Self, askama::Error> {
        AlertPage::with(
            layout,
            tree,
            comments,
            actions,
            sections,
            PageOptions::default(),
        )
    }

    /// The page drawn with `options`.
    pub fn with(
        layout: Layout,
        tree: &AlertTree,
        comments: &[ObservableComment],
        actions: &ObservableActions,
        sections: &BTreeMap<String, bool>,
        options: PageOptions<'_>,
    ) -> Result<Self, askama::Error> {
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
        let tree_section = section(TREE_SECTION);
        let mode = options.tree.unwrap_or(if tree_section.open {
            TreeMode::Full
        } else {
            TreeMode::Detections
        });
        let builtin = crate::icons::PivotIcons::builtin();
        let icons = options.icons.unwrap_or(&builtin);
        let view = tree_view_drawn(tree, comments, actions, icons, mode);
        let (_, version) = AlertTreeFragment { tree: view.clone() }.render_versioned()?;
        let time =
            |time: chrono::DateTime<chrono::Utc>| time.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let disposition = summary
            .disposition
            .clone()
            .unwrap_or_else(|| "OPEN".to_owned());
        let analysis = format!("{:?}", summary.analysis).to_lowercase();
        let alert_type = tree.alert_type().map(str::to_owned);
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
                value: analysis.clone(),
            },
            Detail {
                name: "Disposition",
                value: disposition.clone(),
            },
            // ace3's alert.html says who owns the alert (PLAN.md 7.17)
            Detail {
                name: "Owner",
                value: match (&summary.owner, summary.owned_at) {
                    (Some(owner), Some(at)) => format!("{}, since {}", owner.name, time(at)),
                    (Some(owner), None) => owner.name.clone(),
                    (None, _) => "nobody".to_owned(),
                },
            },
            // ace3's alert.html has the queue among its details (PLAN.md 7.13)
            Detail {
                name: "Queue",
                value: summary.queue.clone(),
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
        // ace3's alert.html: the alert type, and the tool and instance that made it
        if let Some(kind) = &alert_type {
            details.push(Detail {
                name: "Alert type",
                value: kind.clone(),
            });
        }
        for (name, key) in [("Source", "tool"), ("Instance", "tool_instance")] {
            if let Some(value) = tree.origin.get(key).and_then(|v| v.as_str())
                && !value.is_empty()
            {
                details.push(Detail {
                    name,
                    value: value.to_owned(),
                });
            }
        }
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
        let builtin;
        let summaries = match options.summaries {
            Some(summaries) => summaries,
            None => {
                builtin = Summaries::builtin();
                &builtin
            }
        };
        let drawn = alert_type.as_deref().and_then(|kind| {
            summaries.draw(&SummaryInput {
                alert_type: kind,
                origin: &tree.origin,
                tree,
                remediation: options.remediation,
            })
        });
        let (key_observables, more_observables) = key_observables(tree);
        let mut fired = fired_of_tree(tree);
        let more_fired = fired.len().saturating_sub(MAX_FIRED);
        fired.truncate(MAX_FIRED);
        let ace3;
        let dispositions = match options.dispositions {
            Some(dispositions) => dispositions,
            None => {
                ace3 = ace_service::Dispositions::ace3();
                &ace3
            }
        };
        Ok(AlertPage {
            layout,
            id: summary.id,
            title: summary.title.clone(),
            disposition_css: dispositions.css(summary.disposition.as_deref()).to_owned(),
            disposition,
            queue: summary.queue.clone(),
            owner_name: summary.owner.as_ref().map(|owner| owner.name.clone()),
            owned_since: summary.owned_at.map(time),
            alerted: time(summary.alerted_at),
            analysis,
            alert_type,
            tags: summary.tags.clone(),
            fired,
            more_fired,
            external_links: crate::icons::DrawnLink::of(&tree.alert.pivot_links, icons),
            summary: drawn,
            key_observables,
            more_observables,
            svs_section: section("svs"),
            verdicts_section: section("detections"),
            remediation_section: section("remediation"),
            details_section: section("alert_details"),
            rules_section: section("modifier_rules"),
            tree_section,
            details,
            root_detections,
            modifier_rules,
            ignored_count,
            tree: view,
            version,
            owner: summary
                .owner
                .as_ref()
                .map(|owner| owner.id.0.to_string())
                .unwrap_or_default(),
            verdicts: None,
            svs: None,
            ownership: None,
            dispositions: Vec::new(),
            remediation: options
                .remediation
                .and_then(|coverage| RemediationPanel::of(summary.id, coverage)),
        })
    }

    /// The page with its ownership forms.
    pub fn with_ownership(mut self, ownership: Option<OwnershipForms>) -> Self {
        self.ownership = ownership;
        self
    }

    /// The page with its disposition form's choices.
    pub fn with_dispositions(mut self, dispositions: Vec<String>) -> Self {
        self.dispositions = dispositions;
        self
    }

    /// The page with its SVS banner.
    pub fn with_svs(mut self, svs: Option<crate::svs_alert::SvsBanner>) -> Self {
        self.svs = svs;
        self
    }

    /// The page with its detections' verdicts, which the top's detections then carry.
    pub fn with_verdicts(mut self, verdicts: VerdictsView) -> Self {
        verdicts_onto(&mut self.fired, &verdicts);
        self.verdicts = Some(verdicts);
        self
    }

    /// The stream's `t`: the tree the page drew, said only when it's the whole one.
    pub fn stream_tree(&self) -> &'static str {
        if self.tree.full && self.tree.prunable {
            "&t=full"
        } else {
            ""
        }
    }

    /// One line on what the verdicts panel holds.
    pub fn verdicts_hint(&self) -> String {
        let Some(verdicts) = &self.verdicts else {
            return String::new();
        };
        let count = |verdict: &str| {
            verdicts
                .rows
                .iter()
                .filter(|r| r.verdict == verdict)
                .count()
        };
        let mut parts = vec![format!(
            "{}{} detection{}",
            verdicts.rows.len(),
            if verdicts.more { "+" } else { "" },
            if verdicts.rows.len() == 1 { "" } else { "s" }
        )];
        for (verdict, label) in [("tp", "TP"), ("fp", "FP"), ("", "with no verdict")] {
            let n = count(verdict);
            if n > 0 {
                parts.push(format!("{n} {label}"));
            }
        }
        if verdicts.unconfirmed > 0 {
            parts.push(format!("{} unconfirmed", verdicts.unconfirmed));
        }
        parts.join(" · ")
    }

    /// One line on what the details panel holds.
    pub fn details_hint(&self) -> String {
        let named = |name: &str| {
            self.details
                .iter()
                .find(|d| d.name == name)
                .map(|d| d.value.as_str())
                .unwrap_or_default()
        };
        format!(
            "{} mode · {} observables · {} detections · event time {}",
            named("Analysis mode"),
            named("Observables"),
            named("Detections"),
            named("Event time"),
        )
    }

    /// One line on what the SVS panel holds.
    pub fn svs_hint(&self) -> String {
        let Some(svs) = &self.svs else {
            return String::new();
        };
        match (svs.runs.first(), svs.mismatches.len()) {
            (Some(run), 0) if svs.runs.len() == 1 => {
                format!("test run of {}, {}", run.test, run.state)
            }
            (Some(_), 0) => format!("{} test runs", svs.runs.len()),
            (_, mismatches) if mismatches > 0 => format!(
                "{mismatches} marker{} that disagree{} with a run",
                if mismatches == 1 { "" } else { "s" },
                if mismatches == 1 { "s" } else { "" }
            ),
            _ => "tagged by the core".to_owned(),
        }
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
    let verdicts =
        match crate::verdicts::read(&gui, &viewer, id, tree.alert.summary.disposition.as_deref())
            .await
        {
            Ok(verdicts) => verdicts,
            Err(error) => return Failure::from_service(error, &parts).into_response(),
        };
    let svs = match crate::svs_alert::read(&gui, &viewer, id, &tree.alert.summary.tags).await {
        Ok(svs) => svs,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let viewer_id = match &viewer.actor {
        ace_service::Actor::User { id, .. } => Some(*id),
        _ => None,
    };
    let ownership = crate::list::owner_options(&gui, &viewer)
        .await
        .map(|choices| OwnershipForms {
            mine: tree
                .alert
                .summary
                .owner
                .as_ref()
                .is_some_and(|owner| Some(owner.id) == viewer_id),
            users: choices.iter().map(crate::list::owner_option).collect(),
        });
    // what remediation did with the alert's targets, for a viewer who may read it; without it the
    // page has no remediation panel and an email's summary no delivered copies
    let remediation = match gui.service.remediation_coverage(actor, &[id]).await {
        Ok(mut coverage) => coverage.remove(&id),
        Err(ServiceError::PermissionDenied { .. }) => None,
        Err(error) => {
            tracing::warn!(%actor, "reading an alert's remediation coverage failed: {error}");
            None
        }
    };
    // `?tree=full` or `?tree=detections`; anything else follows the viewer's pin
    let asked = parts
        .uri
        .query()
        .and_then(|query| serde_urlencoded::from_str::<Vec<(String, String)>>(query).ok())
        .and_then(|query| {
            query
                .iter()
                .find(|(key, _)| key == "tree")
                .and_then(|(_, value)| TreeMode::named(value))
        });
    let options = PageOptions {
        tree: asked,
        summaries: Some(&gui.summaries),
        dispositions: Some(gui.service.dispositions()),
        remediation: remediation.as_ref(),
        icons: Some(gui.icons()),
    };
    let dispositions = if ownership.is_some() {
        gui.service.dispositions().selectable()
    } else {
        Vec::new()
    };
    match AlertPage::with(
        viewer.layout,
        &tree,
        &comments,
        &gui.actions,
        &sections,
        options,
    ) {
        Ok(page) => render(
            &page
                .with_verdicts(verdicts)
                .with_svs(svs)
                .with_ownership(ownership)
                .with_dispositions(dispositions),
        ),
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
    /// Why the module said it failed, shown above its details, as ace3's analysis page does.
    pub error: Option<String>,
    /// For a result from the analysis cache, when the run it was kept from ended.
    pub cached: Option<String>,
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
            error: result.error.clone(),
            cached: result.cached_at.map(when_cached),
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
    /// The tree the client's page drew.
    mode: TreeMode,
    /// Who the client knows the alert's owner to be: the one its page was drawn with, then the one the
    /// last notice named.
    owner: Option<Uuid>,
    /// An event of the last read still to send: the notice, when the tree went first.
    pending: Option<Event>,
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
            if let Some(event) = self.pending.take() {
                return Some((Ok(event), self));
            }
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
                        tree: tree_view_drawn(
                            &tree,
                            &comments,
                            &self.gui.actions,
                            self.gui.icons(),
                            self.mode,
                        ),
                    };
                    let (html, version) = match fragment.render_versioned() {
                        Ok(drawn) => drawn,
                        Err(error) => {
                            tracing::error!("an alert tree couldn't be drawn: {error}");
                            return None;
                        }
                    };
                    let mut events = Vec::with_capacity(2);
                    if version != self.version {
                        self.version = version;
                        events.push(patch_elements(&html, Some(&self.version)));
                    }
                    // the alert has an owner the page doesn't know of: ace3's "Alert Ownership Changed!"
                    if let Some(notice) = OwnerNoticeFragment::of(&tree.alert.summary, self.owner) {
                        match notice.render() {
                            Ok(html) => {
                                self.owner = tree.alert.summary.owner.as_ref().map(|o| o.id.0);
                                // no id: a reconnect still says which tree the page has
                                events.push(patch_elements(&html, None));
                            }
                            Err(error) => {
                                tracing::error!("an ownership notice couldn't be drawn: {error}");
                                return None;
                            }
                        }
                    }
                    let mut events = events.into_iter();
                    let Some(first) = events.next() else {
                        continue;
                    };
                    self.pending = events.next();
                    return Some((Ok(first), self));
                }
            }
        }
    }
}

/// A `datastar-patch-elements` event that morphs the element of the fragment's id. Each line of the HTML
/// is a `data: elements` line; a carriage return can't be in one, so it's written as its entity, which
/// is the same text inside an element or an attribute. The tree's event has its version as its id; the
/// ownership notice's has none.
fn patch_elements(html: &str, version: Option<&str>) -> Event {
    let data = html
        .replace('\r', "&#13;")
        .lines()
        .map(|line| format!("elements {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let event = Event::default().event("datastar-patch-elements");
    match version {
        Some(version) => event.id(version),
        None => event,
    }
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
    let query: Vec<(String, String)> = parts
        .uri
        .query()
        .and_then(|query| serde_urlencoded::from_str(query).ok())
        .unwrap_or_default();
    let named = |name: &str| {
        query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    // A reconnect says what it last had; the page's own version is in the URL.
    let version = parts
        .headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| named("v"))
        .unwrap_or_default();
    // the tree the page drew: the whole one says so, and anything else is the detections' branches
    let mode = named("t")
        .and_then(|mode| TreeMode::named(&mode))
        .unwrap_or(TreeMode::Detections);
    // who owned the alert when the page was drawn; anything but a uuid is nobody
    let owner = named("o").and_then(|owner| owner.parse::<Uuid>().ok());
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
        mode,
        owner,
        pending: None,
        dirty: true,
        drawn_at: None,
        heartbeat,
        _admitted: admitted,
    };
    Sse::new(stream::unfold(state, Streaming::next)).into_response()
}
