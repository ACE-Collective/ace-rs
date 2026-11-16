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
//! type listed here takes its place. A summary keeps the rules a view keeps (`crate::analysis`): no
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

/// What a summary is drawn from: the alert's type, what its submitter said about it, its tree, and
/// what remediation did with its targets, when the viewer may read that.
#[derive(Debug, Clone, Copy)]
pub struct SummaryInput<'a> {
    pub alert_type: &'a str,
    /// `analysis.roots.origin`: the alert type, tool and details as the submitter gave them.
    pub origin: &'a Value,
    pub tree: &'a AlertTree,
    pub remediation: Option<&'a Coverage>,
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

    type View<'a>: Template;

    /// The summary of this alert, or None when the alert holds nothing it shows, which leaves the
    /// page its default.
    fn view<'a>(alert: &SummaryInput<'a>) -> Option<Self::View<'a>>;
}

/// One alert type's summary in a `Summaries`.
#[derive(Clone, Copy)]
pub struct SummaryEntry {
    pub alert_type: &'static str,
    draw: fn(&SummaryInput<'_>) -> Option<Result<String, String>>,
}

impl SummaryEntry {
    pub fn of<T: AlertSummary>() -> Self {
        SummaryEntry {
            alert_type: T::ALERT_TYPE,
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

/// The binary's alert summaries, by alert type.
#[derive(Debug, Clone)]
pub struct Summaries {
    entries: BTreeMap<&'static str, SummaryEntry>,
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
        }
    }

    /// The open-source summaries: mailbox alerts and hunt alerts.
    pub fn builtin() -> Self {
        Summaries::empty()
            .with(SummaryEntry::of::<MailboxSummary>())
            .with(SummaryEntry::of::<HuntSummary>())
    }

    /// These summaries with `entry`, which takes the place of any for the same alert type.
    pub fn with(mut self, entry: SummaryEntry) -> Self {
        self.entries.insert(entry.alert_type, entry);
        self
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

    /// The summary of an alert by its type, or None for the page's default: no type, no summary for
    /// it, nothing to show, or a summary that failed, which is logged.
    pub fn draw(&self, alert: &SummaryInput<'_>) -> Option<DrawnSummary> {
        let chosen = self.chosen(alert.alert_type)?;
        let entry = self.entries.get(chosen)?;
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
    /// The registered type that drew it.
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
    /// What became of it, in ace3's words, such as `remediated` or `not attempted`.
    pub state: &'static str,
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
    let delivered = text("env_rcpt_to");
    if delivered != text("to") {
        add("Delivered to", delivered);
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
        let paths: Vec<&str> = added
            .iter()
            .map(|observable| {
                observable
                    .files
                    .first()
                    .map_or(observable.value.as_str(), |file| file.path.as_str())
            })
            .collect();
        let index = EmailAnalysis::body_of(&paths)?;
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
                ("remediated", "coverage-remediated")
            } else if target.failed {
                ("failed", "coverage-failed")
            } else if target.not_found {
                ("not in mailbox", "coverage-unremediated")
            } else if target.remediating {
                ("remediating", "coverage-pending")
            } else if target.pending {
                ("watching", "coverage-pending")
            } else if target.attempted {
                ("not remediated", "coverage-unremediated")
            } else {
                ("not attempted", "coverage-unremediated")
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
    pub playbook: Option<String>,
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
        playbook: text(&origin["extensions"]["playbook_url"]).and_then(|url| web_link(&url)),
        window: query.as_deref().and_then(query_window),
        query: query.map(|query| clip(&query, MAX_BLOCK)),
        events: events.len(),
        event,
        more_fields,
        all_events: (events.len() > 1).then(|| clip(&json_text(&details["events"]), MAX_JSON)),
    })
}
