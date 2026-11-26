//! The alert page's summary, chosen by the alert's type (the owner's UI direction of 2026-11-15): ace3's
//! per-alert-type templates, `app/templates/analysis/custom/<alert_type>.html`.
//!
//! What decides an email alert differs from what decides a hunt alert, so the block under the page's
//! detections is drawn by the alert's type. An alert's type is its origin's `alert_type`
//! (`ace_service::AlertTree::alert_type`), what its submitter said: `mailbox` for a mailbox root, and a
//! hunt's own `alert_type`, such as `hunter - splunk - v2`.
//!
//! `Summaries` is plain data built from the binary's list, as `Views` is. A type is looked up as ace3
//! does (`GUIAlertPresenter.template_path`): the whole type first, then with its last ` - ` part taken
//! off, and again, so `hunter - splunk - aws` finds `hunter - splunk - aws`, then `hunter - splunk`,
//! then `hunter`. A type with no summary, an alert with no type, and a summary that has nothing to
//! show or fails all get the page's default, its key observables.
//!
//! Two are ported, `Summaries::builtin`:
//! - `mailbox`, from ace3's `email_alert.html`: who sent the message and to whom, its subject, how it
//!   authenticated, its attachments, which of its parts is its body, its headers, and what remediation
//!   did with its delivered copies.
//! - `hunter`, from ace3's `hunter_splunk.html`, for every hunt type since each submits the same
//!   details: the hunt, where it searched, its query as it ran with its time window, and the matched
//!   event's fields.
//!
//! ace3's brotex, bro_smtp, http, virustotal, o365_security, graph_resource and saq_debug templates are
//! left out (the owner's decision of 2026-11-15).
//!
//! A site adds its own through `ace_app::App::alert_summary`, as it adds an analysis view; one for a
//! type listed here takes its place.
//!
//! **By name** (PLAN.md decision 40). ace3 draws an alert with the template its hunt names in
//! `alert_template` before it looks at the alert's type, such as a site's `example/ticket.html`.
//! A summary is registered under such a name with `ace_app::App::alert_template`, and an alert whose
//! submission's `extensions.alert_template` names it has that summary, whatever its type. The hunt
//! summary answers to ace3's own [`HUNTER_TEMPLATE`]. A summary keeps the rules a view keeps (`crate::analysis`): no
//! `style` attribute and no script, every value through askama, what can be large bounded. A URL from
//! an alert is a link only when it starts with `http://` or `https://`, and text otherwise.

use std::collections::BTreeMap;
use std::fmt;

use ace_results::types::email::EmailAnalysis;
use ace_service::{AlertObservable, AlertTree, Coverage};
use askama::Template;
use serde_json::Value;

use super::{Clipped, MAX_JSON, ViewHtml, clip, json_text};

/// The most rows of one list a summary shows: it has to fit a screen with the rest of the page's top.
pub const MAX_SUMMARY_ROWS: usize = 8;
/// The most fields of a matched event a hunt's summary shows before the rest fold away.
pub const MAX_EVENT_FIELDS: usize = 16;
/// The most bytes of one value a summary shows.
pub const MAX_VALUE: usize = 400;
/// The most bytes of a query or of an email's headers a summary shows.
pub const MAX_BLOCK: usize = 16 << 10;

/// The most emails whose body text a summary that reads them gets (PLAN.md decision 55).
pub const MAX_BODY_EMAILS: usize = MAX_SUMMARY_ROWS;
/// The most bytes of one body part a summary gets; the rest is counted (`EmailBody::more`).
pub const MAX_BODY_BYTES: usize = 64 << 10;

/// What a summary is drawn from: the alert's type, what its submitter said about it, its tree, what
/// remediation did with its targets, when the viewer may read that, and the text of its emails' bodies
/// when the summary reads them. Built with [`SummaryInput::new`] and the methods after it, so a field
/// added here doesn't break a site's test.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SummaryInput<'a> {
    pub alert_type: &'a str,
    /// `analysis.roots.origin`: the alert type, tool and details as the submitter gave them.
    pub origin: &'a Value,
    pub tree: &'a AlertTree,
    pub remediation: Option<&'a Coverage>,
    /// The body parts of the tree's emails, read for a summary that declares
    /// [`AlertSummary::READS_EMAIL_BODIES`]; empty for any other.
    pub bodies: &'a [EmailBody],
}

impl<'a> SummaryInput<'a> {
    /// An alert's input with no remediation and no bodies.
    pub fn new(alert_type: &'a str, origin: &'a Value, tree: &'a AlertTree) -> Self {
        SummaryInput {
            alert_type,
            origin,
            tree,
            remediation: None,
            bodies: &[],
        }
    }

    /// With what remediation did with the alert's targets.
    pub fn with_remediation(mut self, remediation: Option<&'a Coverage>) -> Self {
        self.remediation = remediation;
        self
    }

    /// With its emails' body texts.
    pub fn with_bodies(mut self, bodies: &'a [EmailBody]) -> Self {
        self.bodies = bodies;
        self
    }

    /// The body parts of the email result `result`, in the order the email had them.
    pub fn bodies_of(&self, result: i64) -> impl Iterator<Item = &'a EmailBody> + 'a {
        self.bodies.iter().filter(move |body| body.result == result)
    }
}

/// One body part of an email in an alert, as text, for a summary that shows it (PLAN.md decision 55):
/// ace3's `EmailAnalysis.body_text` and `body_html`, which its alert templates read from the part's
/// file. At most [`MAX_BODY_BYTES`] of it, decoded as UTF-8 with each byte that isn't replaced by
/// U+FFFD, where ace3 drops them; an HTML part is its source, which a summary shows as text and never
/// as markup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailBody {
    /// The `email_analysis` result whose email it is.
    pub result: i64,
    /// The part's file observable.
    pub observable: i64,
    /// Its path in the alert.
    pub path: String,
    /// True for the `text/html` part, false for the `text/plain` one.
    pub html: bool,
    pub text: String,
    /// The bytes past what `text` holds.
    pub more: u64,
}

/// The body parts an alert's summary may show, which [`body_parts`] picks: each email result's first
/// plain text part and its first HTML part, of at most [`MAX_BODY_EMAILS`] emails in the tree's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyPart {
    pub result: i64,
    pub observable: i64,
    pub path: String,
    pub html: bool,
}

/// The body parts to read for a summary (`BodyPart`), as ace3's `EmailAnalysis.body_text` and
/// `body_html` take the first of each kind (`_body_part_types`).
pub fn body_parts(tree: &AlertTree) -> Vec<BodyPart> {
    let mut parts = Vec::new();
    let results = tree.observables.iter().flat_map(|observable| {
        observable
            .results
            .iter()
            .filter(|result| result.analysis_type == "email_analysis")
    });
    for result in results.take(MAX_BODY_EMAILS) {
        let (added, paths) = added_files(tree, result);
        let recorded = recorded_parts(result);
        let kinds = EmailAnalysis::body_parts_in(recorded.as_deref(), &paths);
        for html in [false, true] {
            if let Some((index, _)) = kinds.iter().find(|(_, is_html)| *is_html == html) {
                parts.push(BodyPart {
                    result: result.id,
                    observable: added[*index].id,
                    path: paths[*index].to_owned(),
                    html,
                });
            }
        }
    }
    parts
}

/// A body part's first bytes as text, and how many of them it holds: invalid UTF-8 replaced, and a
/// character the cut split left out.
pub fn body_text(bytes: &[u8]) -> (String, usize) {
    let mut whole = bytes;
    // the cut fell inside a character: leave that character out
    for back in 1..=3.min(bytes.len()) {
        let start = bytes.len() - back;
        if let Err(e) = std::str::from_utf8(&bytes[start..])
            && e.error_len().is_none()
            && e.valid_up_to() == 0
        {
            whole = &bytes[..start];
            break;
        }
    }
    (String::from_utf8_lossy(whole).into_owned(), whole.len())
}

/// The files a result added, and their paths in the alert, in the order it added them.
fn added_files<'t>(
    tree: &'t AlertTree,
    result: &ace_service::ModuleResult,
) -> (Vec<&'t AlertObservable>, Vec<&'t str>) {
    let added: Vec<&AlertObservable> = tree
        .additions
        .iter()
        .filter(|addition| addition.result == result.id)
        .filter_map(|addition| {
            tree.observables
                .iter()
                .find(|o| o.id == addition.observable)
        })
        .filter(|observable| observable.kind == "file")
        .collect();
    let paths = added
        .iter()
        .map(|observable| {
            observable
                .files
                .first()
                .map_or(observable.value.as_str(), |file| file.path.as_str())
        })
        .collect();
    (added, paths)
}

/// The parts an email result records, or None for a result made before it recorded them.
fn recorded_parts(
    result: &ace_service::ModuleResult,
) -> Option<Vec<ace_results::types::email::EmailPart>> {
    result
        .details
        .get("parts")
        .filter(|parts| !parts.is_null())
        .and_then(|parts| serde_json::from_value(parts.clone()).ok())
}

/// An alert type's summary: the askama template that draws what decides an alert of that type.
///
/// A site's summary names its type and builds its template from the alert:
///
/// ```text
/// #[derive(Template)]
/// #[template(path = "ticket_summary.html")]
/// pub struct TicketSummaryView<'a> { queue: &'a str }
///
/// pub struct TicketSummary;
/// impl AlertSummary for TicketSummary {
///     const ALERT_TYPE: &'static str = "example - ticket";
///     type View<'a> = TicketSummaryView<'a>;
///     fn view<'a>(alert: &SummaryInput<'a>) -> Option<TicketSummaryView<'a>> {
///         alert.origin["details"]["queue"].as_str().map(|queue| TicketSummaryView { queue })
///     }
/// }
/// ```
///
/// and its binary's list names it, `App::new().alert_summary::<TicketSummary>()`, as
/// `ace-site-example` does.
pub trait AlertSummary {
    /// The alert type it draws, and every type that starts with it and ` - `.
    const ALERT_TYPE: &'static str;

    /// Whether it shows its emails' body text: the page then reads each email's first plain text and
    /// HTML body part, bounded, into [`SummaryInput::bodies`] (PLAN.md decision 55). Off, the page reads
    /// no file for it.
    const READS_EMAIL_BODIES: bool = false;

    type View<'a>: Template;

    /// The summary of this alert, or None when the alert holds nothing it shows, which leaves the
    /// page its default.
    fn view<'a>(alert: &SummaryInput<'a>) -> Option<Self::View<'a>>;
}

/// One alert type's summary in a `Summaries`.
#[derive(Clone, Copy)]
pub struct SummaryEntry {
    pub alert_type: &'static str,
    /// Its `AlertSummary::READS_EMAIL_BODIES`.
    pub reads_email_bodies: bool,
    draw: fn(&SummaryInput<'_>) -> Option<Result<String, String>>,
}

impl SummaryEntry {
    pub fn of<T: AlertSummary>() -> Self {
        SummaryEntry {
            alert_type: T::ALERT_TYPE,
            reads_email_bodies: T::READS_EMAIL_BODIES,
            draw: draw_as::<T>,
        }
    }
}

impl fmt::Debug for SummaryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SummaryEntry")
            .field("alert_type", &self.alert_type)
            .finish_non_exhaustive()
    }
}

fn draw_as<T: AlertSummary>(alert: &SummaryInput<'_>) -> Option<Result<String, String>> {
    let view = T::view(alert)?;
    Some(
        view.render()
            .map_err(|error| format!("its summary failed: {error}")),
    )
}

/// The binary's alert summaries, by alert type, and by template name.
#[derive(Debug, Clone)]
pub struct Summaries {
    entries: BTreeMap<&'static str, SummaryEntry>,
    named: BTreeMap<&'static str, SummaryEntry>,
}

/// ace3's name for its hunter template, which hunts name in `alert_template` and the open-source hunt
/// summary answers to.
pub const HUNTER_TEMPLATE: &str = "analysis/custom/hunter_splunk.html";

/// The template a submission names in its origin, ace3's root `extensions.alert_template`
/// (`saq/gui/alert.py`'s `KEY_ALERT_TEMPLATE`), which a hunt's `alert_template` sets.
pub fn named_template(origin: &Value) -> Option<&str> {
    origin
        .pointer("/extensions/alert_template")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

impl Default for Summaries {
    fn default() -> Self {
        Summaries::builtin()
    }
}

impl Summaries {
    /// No summaries at all, so every alert has the default.
    pub fn empty() -> Self {
        Summaries {
            entries: BTreeMap::new(),
            named: BTreeMap::new(),
        }
    }

    /// The open-source summaries: mailbox alerts and hunt alerts, the hunt summary also as ace3's
    /// [`HUNTER_TEMPLATE`].
    pub fn builtin() -> Self {
        Summaries::empty()
            .with(SummaryEntry::of::<MailboxSummary>())
            .with(SummaryEntry::of::<HuntSummary>())
            .with_template(HUNTER_TEMPLATE, SummaryEntry::of::<HuntSummary>())
    }

    /// These summaries with `entry`, which takes the place of any for the same alert type.
    pub fn with(mut self, entry: SummaryEntry) -> Self {
        self.entries.insert(entry.alert_type, entry);
        self
    }

    /// These summaries with `entry` under the template name `name` (PLAN.md decision 40), which takes
    /// the place of any of that name. An alert whose submission names it in `alert_template` has it.
    pub fn with_template(mut self, name: &'static str, entry: SummaryEntry) -> Self {
        self.named.insert(name, entry);
        self
    }

    /// Every template name with a summary.
    pub fn templates(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.named.keys().copied()
    }

    /// Every alert type with a summary.
    pub fn types(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.entries.keys().copied()
    }

    /// The alert type whose summary draws `alert_type`: itself, or the longest registered type it
    /// starts with at a ` - `, as ace3 looks for `hunter_splunk_aws.html`, then `hunter_splunk.html`,
    /// then `hunter.html`.
    pub fn chosen(&self, alert_type: &str) -> Option<&'static str> {
        let mut wanted = alert_type.trim();
        loop {
            if let Some(entry) = self.entries.get(wanted) {
                return Some(entry.alert_type);
            }
            wanted = wanted.rsplit_once(" - ")?.0.trim_end();
        }
    }

    /// Whether the summary `draw` would try first for an alert, by the template it names or else its
    /// type, or the one by type it falls back to, reads its emails' bodies, so the page reads them
    /// only for such a summary.
    pub fn reads_email_bodies(&self, alert_type: &str, origin: &Value) -> bool {
        let named = named_template(origin)
            .and_then(|name| self.named.get(name))
            .is_some_and(|entry| entry.reads_email_bodies);
        let typed = self
            .chosen(alert_type)
            .and_then(|chosen| self.entries.get(chosen))
            .is_some_and(|entry| entry.reads_email_bodies);
        named || typed
    }

    /// The summary of an alert, chosen as ace3's `GUIAlertPresenter.template_path` chooses its
    /// template: the template its submission names (`alert_template`), when a summary has that name,
    /// then by its type. None is the page's default: no summary for either, nothing to show, or a
    /// summary that failed, which is logged. A name with no summary is logged and falls through to
    /// the type, where ace3 would fail to draw the page.
    pub fn draw(&self, alert: &SummaryInput<'_>) -> Option<DrawnSummary> {
        if let Some(name) = named_template(alert.origin) {
            match self.named.get_key_value(name) {
                Some((name, entry)) => {
                    if let Some(drawn) = Self::draw_entry(entry, name, alert) {
                        return Some(drawn);
                    }
                }
                None => tracing::warn!(
                    alert_type = alert.alert_type,
                    template = name,
                    "an alert names a template this binary has no summary for; its type chooses"
                ),
            }
        }
        let chosen = self.chosen(alert.alert_type)?;
        let entry = self.entries.get(chosen)?;
        Self::draw_entry(entry, chosen, alert)
    }

    fn draw_entry(
        entry: &SummaryEntry,
        chosen: &'static str,
        alert: &SummaryInput<'_>,
    ) -> Option<DrawnSummary> {
        match (entry.draw)(alert)? {
            Ok(html) => Some(DrawnSummary {
                alert_type: chosen,
                html: ViewHtml(html),
            }),
            Err(error) => {
                tracing::warn!(
                    alert_type = alert.alert_type,
                    "an alert summary fell back to the default: {error}"
                );
                None
            }
        }
    }
}

/// An alert's summary as its page places it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawnSummary {
    /// The registered alert type, or template name, that drew it.
    pub alert_type: &'static str,
    pub html: ViewHtml,
}

// ---- what the summaries share ----

/// One row of a summary's facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryField {
    pub name: String,
    pub value: String,
    /// The whole value when `value` was cut, for the row's `title`.
    pub full: Option<String>,
}

fn summary_field(name: &str, value: &str) -> SummaryField {
    let shown = clip(value, MAX_VALUE);
    SummaryField {
        name: name.to_owned(),
        full: (shown.more > 0).then(|| clip(value, MAX_BLOCK).text),
        value: if shown.more > 0 {
            format!("{}…", shown.text)
        } else {
            shown.text
        },
    }
}

/// A JSON value as one line of text: a string as it is, a list's items joined, anything else as JSON.
fn text_of_json(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(text_of_json).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        Value::Bool(_) | Value::Number(_) => Some(value.to_string()),
        Value::Object(_) => Some(value.to_string()),
    }
    .filter(|text| !text.trim().is_empty())
}

/// A URL from an alert as a link's address: only `http://` and `https://` are one.
fn web_link(url: &str) -> Option<String> {
    let url = url.trim();
    (url.starts_with("https://") || url.starts_with("http://")).then(|| url.to_owned())
}

/// Where the tree draws an observable in full, on the page that shows the whole tree.
fn tree_anchor(tree: &AlertTree, observable: i64) -> String {
    format!("/alerts/{}?tree=full#o{observable}", tree.alert.summary.id)
}

// ---- mailbox: ace3's email_alert.html ----

/// A mailbox alert's summary.
pub struct MailboxSummary;

/// One attachment of the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryAttachment {
    pub name: String,
    pub content_type: String,
    pub size: String,
}

/// One delivered copy of the message and what remediation did with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// Whose mailbox it went to.
    pub recipient: String,
    /// What became of it, in ace3's words, such as `remediated` or `not attempted`, or what the
    /// journal says of an address that didn't receive its own copy.
    pub state: String,
    /// The badge's class.
    pub class: &'static str,
    /// What confirmed a remediation.
    pub sources: String,
}

/// `mailbox`, from ace3's `email_alert.html`.
#[derive(Debug, Template)]
#[template(path = "summary/mailbox.html")]
pub struct MailboxSummaryView {
    pub subject: Option<String>,
    pub fields: Vec<SummaryField>,
    /// SPF, DKIM, DMARC and the composite result, each as (name, result, whether it passed).
    pub authentication: Vec<(&'static str, String, bool)>,
    /// What the email analysis concluded of the sender, such as a spoofed internal address.
    pub warnings: Vec<&'static str>,
    pub attachments: Vec<SummaryAttachment>,
    pub more_attachments: usize,
    /// The part ace3 calls the body: its name and where the tree draws it.
    pub body: Option<(String, String)>,
    pub headers: Option<Clipped>,
    /// The remediation badge of the alert, ace3's `_remediation_badge.html`.
    pub coverage: Option<crate::remediation::CoverageBadge>,
    pub deliveries: Vec<Delivery>,
    pub more_deliveries: usize,
    /// The page that finds the alert's remediation targets.
    pub remediate: String,
}

impl AlertSummary for MailboxSummary {
    const ALERT_TYPE: &'static str = "mailbox";
    type View<'a> = MailboxSummaryView;

    fn view<'a>(alert: &SummaryInput<'a>) -> Option<MailboxSummaryView> {
        mailbox_view(alert)
    }
}

/// The observable and result of the tree's email analysis: the one on the original email first.
fn email_result(tree: &AlertTree) -> Option<(&AlertObservable, &ace_service::ModuleResult)> {
    let results = || {
        tree.observables.iter().flat_map(|observable| {
            observable
                .results
                .iter()
                .filter(|result| result.analysis_type == "email_analysis")
                .map(move |result| (observable, result))
        })
    };
    results()
        .find(|(observable, _)| observable.directives.iter().any(|d| d == "original_email"))
        .or_else(|| results().next())
}

fn mailbox_view(alert: &SummaryInput<'_>) -> Option<MailboxSummaryView> {
    let tree = alert.tree;
    let analyzed = email_result(tree);
    // the mailbox module merges the email's details into the root's; before it has, the email's own
    let email = match &alert.origin["details"]["email"] {
        Value::Object(_) => &alert.origin["details"]["email"],
        _ => &analyzed?.1.details["email"],
    };
    if !email.is_object() {
        return None;
    }
    let text = |name: &str| text_of_json(&email[name]);
    let mut fields = Vec::new();
    let mut add = |name: &str, value: Option<String>| {
        if let Some(value) = value {
            fields.push(summary_field(name, &value));
        }
    };
    let from = text("from");
    let sender = text("env_mail_from");
    add("From", from.clone());
    if sender != from {
        add("Envelope sender", sender);
    }
    add("Reply-To", text("reply_to"));
    add("Return-Path", text("return_path"));
    add("To", text("to"));
    add("Cc", text("cc"));
    // ace3's "Delivered to" (aaeef15e): a journal report's delivered mailboxes and what happened
    // to each address it didn't deliver to under that address; else the envelope recipients
    let journal: Option<std::collections::BTreeMap<String, ace_results::types::email::Delivery>> =
        email
            .get("deliveries")
            .filter(|d| d.is_object())
            .and_then(|d| serde_json::from_value(d.clone()).ok());
    match journal {
        Some(journal) => {
            use ace_results::types::email::DeliveryReason;
            let delivered: Vec<&str> = journal
                .iter()
                .filter(|(_, d)| d.reason == DeliveryReason::Delivered)
                .map(|(address, _)| address.as_str())
                .collect();
            add(
                "Delivered to",
                (!delivered.is_empty()).then(|| delivered.join(", ")),
            );
            let notes: Vec<String> = journal
                .iter()
                .filter(|(_, d)| d.reason != DeliveryReason::Delivered)
                .map(|(address, d)| {
                    format!("{address}: {}", d.reason.describe_undelivered(&d.mailboxes))
                })
                .collect();
            add(
                "Not delivered",
                (!notes.is_empty()).then(|| notes.join("; ")),
            );
        }
        None => {
            let delivered = text("env_rcpt_to");
            if delivered != text("to") {
                add("Delivered to", delivered);
            }
        }
    }
    let date = email["headers"].as_array().and_then(|headers| {
        headers.iter().find_map(|header| {
            let name = header.get(0)?.as_str()?;
            name.eq_ignore_ascii_case("date")
                .then(|| header.get(1)?.as_str().map(str::to_owned))
                .flatten()
        })
    });
    add("Date", date);
    add(
        "Message-ID",
        text("message-id").map(|id| id.trim().to_owned()),
    );
    add("Originating IP", text("originating_ip"));
    add(
        "First hop",
        match (text("first_hop_ip"), text("first_hop_helo")) {
            (Some(ip), Some(helo)) => Some(format!("{ip} ({helo})")),
            (ip, helo) => ip.or(helo),
        },
    );

    let authentication = [
        ("SPF", "spf_result"),
        ("DKIM", "dkim_result"),
        ("DMARC", "dmarc_result"),
        ("CompAuth", "compauth_result"),
    ]
    .into_iter()
    .filter_map(|(label, name)| {
        let result = text(name)?;
        let passed = result.eq_ignore_ascii_case("pass");
        Some((label, result, passed))
    })
    .collect();
    let flag = |name: &str| email[name].as_bool() == Some(true);
    let mut warnings = Vec::new();
    if flag("spoofed_internal") {
        warnings.push("spoofed internal sender");
    }
    if flag("authentication_failed") {
        warnings.push("authentication failed");
    }
    if flag("is_anonymous_direct_send") {
        warnings.push("anonymous direct send");
    }

    let log = &email["log_entry"];
    let names: Vec<String> = log["attachment_names"]
        .as_array()
        .map(|names| names.iter().filter_map(text_of_json).collect())
        .unwrap_or_default();
    let at = |list: &str, index: usize| {
        log[list]
            .get(index)
            .and_then(text_of_json)
            .unwrap_or_default()
    };
    let attachments = names
        .iter()
        .take(MAX_SUMMARY_ROWS)
        .enumerate()
        .map(|(index, name)| SummaryAttachment {
            name: clip(name, MAX_VALUE).text,
            content_type: at("attachment_types", index),
            size: at("attachment_sizes", index),
        })
        .collect();

    // ace3's `EmailAnalysis.body`: which of the files the email's result added is the body
    let body = analyzed.and_then(|(_, result)| {
        let (added, paths) = added_files(tree, result);
        // the parts the result records, or, for a result made before it recorded them, the names
        let parts = recorded_parts(result);
        let index = EmailAnalysis::body_in(parts.as_deref(), &paths)?;
        Some((paths[index].to_owned(), tree_anchor(tree, added[index].id)))
    });

    let headers = email["headers"].as_array().and_then(|headers| {
        let mut block = String::new();
        for header in headers {
            let (Some(name), Some(value)) = (
                header.get(0).and_then(Value::as_str),
                header.get(1).and_then(Value::as_str),
            ) else {
                continue;
            };
            block.push_str(name);
            block.push_str(": ");
            block.push_str(value);
            block.push('\n');
            if block.len() > MAX_BLOCK {
                break;
            }
        }
        (!block.is_empty()).then(|| clip(&block, MAX_BLOCK))
    });

    let coverage = alert
        .remediation
        .and_then(crate::remediation::coverage_badge);
    let targets = alert.remediation.map_or(&[][..], |c| c.targets.as_slice());
    let deliveries = targets
        .iter()
        .take(MAX_SUMMARY_ROWS)
        .map(|target| {
            // ace3's words for a target (`TargetCoverage::status_display`)
            let (state, class) = if target.remediated() {
                ("remediated".to_owned(), "coverage-remediated")
            } else if let (true, Some(reason)) = (target.not_delivered, target.undelivered) {
                (reason.describe_undelivered(&[]), "coverage-unremediated")
            } else if target.failed {
                ("failed".to_owned(), "coverage-failed")
            } else if target.not_found {
                ("not in mailbox".to_owned(), "coverage-unremediated")
            } else if target.remediating {
                ("remediating".to_owned(), "coverage-pending")
            } else if target.pending {
                ("watching".to_owned(), "coverage-pending")
            } else if target.attempted {
                ("not remediated".to_owned(), "coverage-unremediated")
            } else {
                ("not attempted".to_owned(), "coverage-unremediated")
            };
            Delivery {
                recipient: clip(target.recipient(), MAX_VALUE).text,
                state,
                class,
                sources: target
                    .sources
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        })
        .collect();

    let subject = text("decoded_subject").or_else(|| text("subject"));
    if subject.is_none() && fields.is_empty() {
        return None;
    }
    Some(MailboxSummaryView {
        subject: subject.map(|subject| clip(&subject, MAX_VALUE).text),
        fields,
        authentication,
        warnings,
        attachments,
        more_attachments: names.len().saturating_sub(MAX_SUMMARY_ROWS),
        body,
        headers,
        coverage,
        deliveries,
        more_deliveries: targets.len().saturating_sub(MAX_SUMMARY_ROWS),
        remediate: format!("/remediations/targets?alert={}", tree.alert.summary.id),
    })
}

// ---- hunter: ace3's hunter_splunk.html ----

/// A hunt alert's summary, for every hunt type.
pub struct HuntSummary;

/// `hunter`, from ace3's `hunter_splunk.html`.
#[derive(Debug, Template)]
#[template(path = "summary/hunt.html")]
pub struct HuntSummaryView {
    /// The hunt and where it searched.
    pub fields: Vec<SummaryField>,
    /// What the hunt's author tells the analyst, the hunt's `description`.
    pub instructions: Option<String>,
    /// The search in the hunt's tool, when the origin has a web address for it.
    pub search_link: Option<String>,
    /// The query's own time window, as it ran.
    pub window: Option<String>,
    pub query: Option<Clipped>,
    /// How many events matched.
    pub events: usize,
    /// The first matched event's fields, then the fields that fold away.
    pub event: Vec<SummaryField>,
    pub more_fields: Vec<SummaryField>,
    /// Every matched event as JSON, when there is more than the first.
    pub all_events: Option<Clipped>,
}

impl AlertSummary for HuntSummary {
    const ALERT_TYPE: &'static str = "hunter";
    type View<'a> = HuntSummaryView;

    fn view<'a>(alert: &SummaryInput<'a>) -> Option<HuntSummaryView> {
        hunt_view(alert)
    }
}

/// The `earliest=` and `latest=` terms of a query as it ran, which are its time window.
fn query_window(query: &str) -> Option<String> {
    let terms: Vec<&str> = query
        .split_whitespace()
        .filter(|term| {
            let name = term.split('=').next().unwrap_or_default();
            term.contains('=') && (name.ends_with("earliest") || name.ends_with("latest"))
        })
        .take(4)
        .collect();
    (!terms.is_empty()).then(|| clip(&terms.join(" "), MAX_VALUE).text)
}

fn hunt_view(alert: &SummaryInput<'_>) -> Option<HuntSummaryView> {
    let origin = alert.origin;
    let details = &origin["details"];
    if !origin.is_object() {
        return None;
    }
    let text = |value: &Value| text_of_json(value);
    let mut fields = Vec::new();
    let mut add = |name: &str, value: Option<String>| {
        if let Some(value) = value {
            fields.push(summary_field(name, &value));
        }
    };
    add("Hunt", text(&origin["description"]));
    add("Alert type", Some(alert.alert_type.to_owned()));
    add(
        "Searched",
        match (text(&origin["tool"]), text(&origin["tool_instance"])) {
            (Some(tool), Some(instance)) => Some(format!("{tool} at {instance}")),
            (tool, instance) => tool.or(instance),
        },
    );
    add(
        "Event time",
        text(&origin["event_time"]).map(|time| match text(&origin["event_time_source"]) {
            Some(source) => format!("{time} ({source})"),
            None => time,
        }),
    );
    add("Queue", text(&origin["queue"]));
    add("Group", text(&origin["group_value"]));
    let query = text(&details["query"]);
    let events = details["events"].as_array().map_or(&[][..], Vec::as_slice);
    let mut event: Vec<SummaryField> = events
        .first()
        .and_then(Value::as_object)
        .map(|first| {
            first
                .iter()
                .filter_map(|(name, value)| Some(summary_field(name, &text_of_json(value)?)))
                .collect()
        })
        .unwrap_or_default();
    let more_fields = if event.len() > MAX_EVENT_FIELDS {
        event.split_off(MAX_EVENT_FIELDS)
    } else {
        Vec::new()
    };
    // an origin with neither a query nor an event is no hunter's: the page's default serves it better
    if query.is_none() && events.is_empty() {
        return None;
    }
    Some(HuntSummaryView {
        fields,
        instructions: text(&origin["instructions"]).map(|text| clip(&text, MAX_BLOCK).text),
        search_link: text(&details["search_link"]).and_then(|url| web_link(&url)),
        window: query.as_deref().and_then(query_window),
        query: query.map(|query| clip(&query, MAX_BLOCK)),
        events: events.len(),
        event,
        more_fields,
        all_events: (events.len() > 1).then(|| clip(&json_text(&details["events"]), MAX_JSON)),
    })
}
