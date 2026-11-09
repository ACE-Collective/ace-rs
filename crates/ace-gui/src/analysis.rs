//! Analysis views (PLAN.md 5.9): how a module's result shows on its page, ace3's analysis templates.
//!
//! Each analysis type has a view, an askama template over the type's own struct, so a template that
//! names a field the type doesn't have fails the build. A type is drawn by its name and version from
//! `Views`, which is plain data built from the binary's list, as `ace_results::Registry` is: nothing
//! registers at import, and a process that never draws a page never builds one. ace3 picks a template
//! through a presenter class that each module registers when it's imported
//! (`register_analysis_presenter`, `saq/analysis/presenter/analysis_presenter.py`), which is the
//! import-time wiring #1032 describes. Here the open-source types' views are `Views::builtin`, and a
//! site adds its own through `ace_app::App::analysis_view`, the same way it adds a module, so the
//! list is fixed when the binary is built.
//!
//! What a view is ported from: `email_analysis.html`, `rdap.html`, `yara_analysis_v3_4.html` and
//! `email_thread.html`, `user.html`, and the Splunk modules' `api_analysis.html`. ace3 draws the other ported modules' results with
//! `default_template.html`, which prints the details with `pprint`; here each has a view of its own
//! fields in the same order, which reads the same and needs no Python repr of bytes.
//!
//! The rules every view keeps, since the page's policy (`headers`) refuses anything else:
//! - No `style` attribute and no script. ace3's inline styles are classes in the stylesheet, and its
//!   collapsing panels are `<details>`, which needs no script. ace3's Splunk table sorts and resizes
//!   its columns with jQuery; here it doesn't.
//! - Every string a module wrote goes through askama's escaper. A view's HTML is placed into its page
//!   as `ViewHtml`, the one type this crate marks as already escaped, which only `Views::draw` makes,
//!   from a template's output.
//! - Bytes read as ace3 shows them. YARA's matched bytes are one character a byte, as ace3's JSON
//!   encoder decodes them (`unicode_escape`), with control characters drawn as symbols as its
//!   presenter does (`visible`). A name that may not be text (`TextOrBytes`) reads as UTF-8 with each
//!   byte that isn't written `\xNN` (`text_of`).
//! - What can be large is bounded, with a note saying what was left out (`clip`, `first`): a text
//!   block at `MAX_TEXT` bytes, a list at `MAX_ITEMS` entries, and the limits each view names. The
//!   whole of anything left out is still in the alert: in the JSON API's result, and for macros and
//!   objects in the files the module added.
//!
//! A type with no view, or details its view can't read, is drawn as its details in JSON, as ace3's
//! `default_template.html` draws them, and the page says why.

use std::collections::BTreeMap;
use std::fmt;

use ace_results::bytes::TextOrBytes;
use ace_results::types::archive::ArchiveAnalysis;
use ace_results::types::brocess::{
    EmailConversationFrequencyAnalysis, EmailThreadAnalysis, Lookalike, ThreadMessage,
};
use ace_results::types::dns::FqdnAnalysis;
use ace_results::types::email::EmailAnalysis;
use ace_results::types::msoffice::MsofficeEncryptionAnalysis;
use ace_results::types::nrd::NrdAnalysis;
use ace_results::types::olevba::{OlevbaAnalysis, OlevbaMacro};
use ace_results::types::pcode::PCodeAnalysis;
use ace_results::types::pdf::PdfAnalysis;
use ace_results::types::rdap::RdapAnalysis;
use ace_results::types::rtf::RtfOleObjectAnalysis;
use ace_results::types::snort::SnortSignatureAnalysis;
use ace_results::types::splunk::{SplunkApiAnalysis, SplunkClickerDetectionAnalysis};
use ace_results::types::user::UserAnalysis;
use ace_results::types::xlm::XlmDeobfuscatorAnalysis;
use ace_results::types::yara::{ScanResult, YaraScanResults};
use ace_results::{AnalysisType, sort_json_keys};
use askama::Template;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The most bytes of one block of text a view shows.
pub const MAX_TEXT: usize = 64 << 10;
/// The most entries of one list a view shows.
pub const MAX_ITEMS: usize = 1000;
/// The most bytes of details the JSON fallback shows.
pub const MAX_JSON: usize = 256 << 10;

/// A result type's view: the askama template that draws its details.
///
/// A site's type implements it beside its module, with a template whose name ends in `.html` and that
/// keeps the rules above:
///
/// ```text
/// #[derive(Template)]
/// #[template(path = "ticket.html")]   // {% for t in analysis.tickets %}<p>{{ t }}</p>{% endfor %}
/// pub struct TicketView<'a> {
///     analysis: &'a TicketAnalysis,
/// }
///
/// impl AnalysisView for TicketAnalysis {
///     type View<'a> = TicketView<'a>;
///     fn view(&self) -> TicketView<'_> {
///         TicketView { analysis: self }
///     }
/// }
/// ```
///
/// and its binary's list names it, `App::new().analysis_view::<TicketAnalysis>()`, as
/// `ace-site-example` does.
pub trait AnalysisView: AnalysisType + DeserializeOwned {
    type View<'a>: Template
    where
        Self: 'a;

    fn view(&self) -> Self::View<'_>;
}

/// One analysis type's view in a `Views`.
#[derive(Clone, Copy)]
pub struct ViewEntry {
    pub name: &'static str,
    pub version: u32,
    draw: fn(&Value) -> Result<String, String>,
}

impl ViewEntry {
    pub fn of<T: AnalysisView>() -> Self {
        ViewEntry {
            name: T::NAME,
            version: T::VERSION,
            draw: draw_as::<T>,
        }
    }
}

impl fmt::Debug for ViewEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewEntry")
            .field("name", &self.name)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn draw_as<T: AnalysisView>(details: &Value) -> Result<String, String> {
    let details = T::deserialize(details).map_err(|e| format!("its details don't read: {e}"))?;
    details
        .view()
        .render()
        .map_err(|e| format!("its view failed: {e}"))
}

/// The binary's views, by analysis type and version.
#[derive(Debug, Clone)]
pub struct Views {
    entries: BTreeMap<(&'static str, u32), ViewEntry>,
}

impl Default for Views {
    fn default() -> Self {
        Views::builtin()
    }
}

impl Views {
    /// No views at all, so every result draws as JSON.
    pub fn empty() -> Self {
        Views {
            entries: BTreeMap::new(),
        }
    }

    /// The views of the open-source modules' types.
    pub fn builtin() -> Self {
        Views::empty()
            .with(ViewEntry::of::<EmailAnalysis>())
            .with(ViewEntry::of::<ArchiveAnalysis>())
            .with(ViewEntry::of::<YaraScanResults>())
            .with(ViewEntry::of::<RdapAnalysis>())
            .with(ViewEntry::of::<FqdnAnalysis>())
            .with(ViewEntry::of::<SnortSignatureAnalysis>())
            .with(ViewEntry::of::<EmailConversationFrequencyAnalysis>())
            .with(ViewEntry::of::<EmailThreadAnalysis>())
            .with(ViewEntry::of::<NrdAnalysis>())
            .with(ViewEntry::of::<UserAnalysis>())
            .with(ViewEntry::of::<SplunkApiAnalysis>())
            .with(ViewEntry::of::<SplunkClickerDetectionAnalysis>())
            .with(ViewEntry::of::<OlevbaAnalysis>())
            .with(ViewEntry::of::<RtfOleObjectAnalysis>())
            .with(ViewEntry::of::<MsofficeEncryptionAnalysis>())
            .with(ViewEntry::of::<XlmDeobfuscatorAnalysis>())
            .with(ViewEntry::of::<PCodeAnalysis>())
            .with(ViewEntry::of::<PdfAnalysis>())
    }

    /// These views with `entry`, which takes the place of any view of the same type and version, so a
    /// site may draw an open-source type its own way.
    pub fn with(mut self, entry: ViewEntry) -> Self {
        self.entries.insert((entry.name, entry.version), entry);
        self
    }

    pub fn has(&self, name: &str, version: u32) -> bool {
        self.entry(name, version).is_some()
    }

    /// Every type with a view, by name and version.
    pub fn types(&self) -> impl Iterator<Item = (&'static str, u32)> + '_ {
        self.entries.keys().copied()
    }

    fn entry(&self, name: &str, version: u32) -> Option<&ViewEntry> {
        self.entries
            .iter()
            .find(|((n, v), _)| *n == name && *v == version)
            .map(|(_, entry)| entry)
    }

    /// A result's details drawn by its type's view, or as JSON when there's none or it fails.
    pub fn draw(&self, analysis_type: &str, version: i32, details: &Value) -> DrawnView {
        let entry = u32::try_from(version)
            .ok()
            .and_then(|version| self.entry(analysis_type, version));
        let fallback = match entry.map(|entry| (entry.draw)(details)) {
            Some(Ok(html)) => {
                return DrawnView {
                    html: ViewHtml(html),
                    fallback: None,
                };
            }
            Some(Err(error)) => {
                tracing::warn!(
                    analysis_type,
                    version,
                    "an analysis view fell back to JSON: {error}"
                );
                format!(
                    "The view of {analysis_type} version {version} couldn't draw this result ({error}), so these are its details."
                )
            }
            None => {
                format!("{analysis_type} version {version} has no view, so these are its details.")
            }
        };
        let json = JsonView {
            json: clip(&json_text(details), MAX_JSON),
        };
        match json.render() {
            Ok(html) => DrawnView {
                html: ViewHtml(html),
                fallback: Some(fallback),
            },
            Err(error) => {
                tracing::error!("a result's JSON couldn't be drawn: {error}");
                DrawnView {
                    html: ViewHtml(String::new()),
                    fallback: Some(fallback),
                }
            }
        }
    }
}

/// A result's view as its page shows it.
#[derive(Debug, Clone)]
pub struct DrawnView {
    pub html: ViewHtml,
    /// Why it's the details as JSON rather than its type's view, when it is.
    pub fallback: Option<String>,
}

/// HTML a template drew, which a page places as it is. Only `Views::draw` makes one, from askama's
/// output, whose every value was escaped, so it's the one type here that askama doesn't escape again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewHtml(String);

impl ViewHtml {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ViewHtml {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl askama::filters::HtmlSafe for ViewHtml {}

// ---- what views share ----

/// Text cut to a limit, with how many bytes were left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clipped {
    pub text: String,
    pub more: usize,
}

/// The first `max` bytes of `text`, cut at a character's start.
pub fn clip(text: &str, max: usize) -> Clipped {
    if text.len() <= max {
        return Clipped {
            text: text.to_owned(),
            more: 0,
        };
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Clipped {
        text: text[..end].to_owned(),
        more: text.len() - end,
    }
}

/// The first `max` items of a list, with how many were left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown<'a, T> {
    pub items: &'a [T],
    pub more: usize,
}

pub fn first<T>(items: &[T], max: usize) -> Shown<'_, T> {
    let shown = items.len().min(max);
    Shown {
        items: &items[..shown],
        more: items.len() - shown,
    }
}

/// A value that may not be text, as UTF-8 with each byte that isn't written `\xNN`.
pub fn text_of(value: &TextOrBytes) -> String {
    match value {
        TextOrBytes::Text(text) => text.clone(),
        TextOrBytes::Bytes(bytes) => bytes_text(bytes),
    }
}

/// Bytes as UTF-8, with each byte that isn't written `\xNN`, as Python's `backslashreplace` does.
pub fn bytes_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        for byte in chunk.invalid() {
            text.push_str(&format!("\\x{byte:02x}"));
        }
    }
    text
}

/// JSON as ace3's `json.dumps(..., indent=4, sort_keys=True)` writes it, near enough: sorted keys,
/// indented.
pub fn json_text(value: &Value) -> String {
    let mut buffer = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
    match serde::Serialize::serialize(&sort_json_keys(value.clone()), &mut serializer) {
        Ok(()) => String::from_utf8(buffer).unwrap_or_default(),
        Err(error) => format!("unwritable JSON: {error}"),
    }
}

/// One character of a matched value as ace3's YARA view draws it (`visible_match_value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Glyph {
    /// Printable text, a run of it.
    Text(String),
    /// A space, which the stylesheet draws a dot over.
    Space,
    /// A symbol for a character that doesn't print, such as `␊` for a newline or `\x85`.
    Symbol(String),
}

/// Bytes as ace3 shows a YARA match: a character a byte, each `U+00XX` as its JSON encoder's
/// `unicode_escape` decodes them, with what doesn't print drawn as a symbol: `U+2400` and on for the
/// control characters, `␡` for DEL, and `\xNN` for the others Python calls unprintable.
pub fn visible(bytes: &[u8]) -> Vec<Glyph> {
    let mut glyphs: Vec<Glyph> = Vec::new();
    for &byte in bytes {
        let glyph = match byte {
            b' ' => Glyph::Space,
            0x00..=0x1f => Glyph::Symbol(
                char::from_u32(0x2400 + u32::from(byte))
                    .unwrap_or('?')
                    .to_string(),
            ),
            0x7f => Glyph::Symbol("\u{2421}".to_owned()),
            0x80..=0xa0 | 0xad => Glyph::Symbol(format!("\\x{byte:02x}")),
            _ => Glyph::Text(char::from(byte).to_string()),
        };
        match (glyphs.last_mut(), glyph) {
            (Some(Glyph::Text(run)), Glyph::Text(more)) => run.push_str(&more),
            (_, glyph) => glyphs.push(glyph),
        }
    }
    glyphs
}

/// A run of one line of a hex dump, marked or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub text: String,
    pub marked: bool,
}

/// `hexdump -C`'s lines for `data`, with the bytes in `marked` marked in both columns, as ace3's
/// `hexdump_line_html` draws them, and the length last. Lines aren't folded into `*`, as there.
pub fn hexdump(data: &[u8], marked: std::ops::Range<usize>) -> Vec<Vec<Segment>> {
    fn push(line: &mut Vec<Segment>, text: &str, marked: bool) {
        match line.last_mut() {
            Some(last) if last.marked == marked => last.text.push_str(text),
            _ => line.push(Segment {
                text: text.to_owned(),
                marked,
            }),
        }
    }
    let mut lines = Vec::new();
    for (row, chunk) in data.chunks(16).enumerate() {
        let offset = row * 16;
        let mut line = Vec::new();
        push(&mut line, &format!("{offset:08x}  "), false);
        let mut text = Vec::new();
        for index in 0..16 {
            let separator = if index == 8 {
                "  "
            } else if index > 0 {
                " "
            } else {
                ""
            };
            let Some(&byte) = chunk.get(index) else {
                push(&mut line, &format!("{separator}  "), false);
                continue;
            };
            let at = offset + index;
            let is_marked = marked.contains(&at);
            push(
                &mut line,
                separator,
                is_marked && at > 0 && marked.contains(&(at - 1)),
            );
            push(&mut line, &format!("{byte:02x}"), is_marked);
            let shown = if (0x20..0x7f).contains(&byte) {
                char::from(byte)
            } else {
                '.'
            };
            text.push((shown, is_marked));
        }
        push(&mut line, "  |", false);
        for (shown, is_marked) in text {
            push(&mut line, &shown.to_string(), is_marked);
        }
        push(&mut line, "|", false);
        lines.push(line);
    }
    lines.push(vec![Segment {
        text: format!("{:08x}", data.len()),
        marked: false,
    }]);
    lines
}

/// A row of a view's table of fields: the field's name and its value as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: &'static str,
    pub value: String,
}

fn field(name: &'static str, value: Option<impl ToString>) -> Option<Field> {
    value.map(|value| Field {
        name,
        value: value.to_string(),
    })
}

fn list(items: &[String]) -> String {
    items.join(", ")
}

// ---- the fallback ----

/// A result's details as JSON, as ace3's `default_template.html` prints them.
#[derive(Debug, Template)]
#[template(path = "analysis/json.html")]
struct JsonView {
    json: Clipped,
}

// ---- email: ace3's email_analysis.html ----

/// `email_analysis`, from ace3's `email_analysis.html`: the summary table, the raw headers, and the
/// attachments ace3 lists in the tree below it.
#[derive(Debug, Template)]
#[template(path = "analysis/email_analysis.html")]
pub struct EmailView<'a> {
    pub analysis: &'a EmailAnalysis,
}

/// One attachment, from the email's log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub content_type: String,
    pub size: String,
    pub sha256: String,
}

impl EmailView<'_> {
    /// The summary rows, as ace3's table has them. ace3's "Subject (Decoded)" row reads
    /// `analysis.decode_subject`, which isn't a property, so it's empty there; here it's the decoded
    /// subject.
    pub fn summary(&self) -> Vec<Field> {
        let Some(email) = &self.analysis.email else {
            return Vec::new();
        };
        let subject = match &email.decoded_subject {
            Some(decoded) => field("Subject (Decoded)", Some(decoded)),
            None => field("Subject", email.subject.as_ref()),
        };
        [
            field("Env Mail From", email.env_mail_from.as_ref()),
            field(
                "Env Rcpt To",
                (!email.env_rcpt_to.is_empty()).then(|| list(&email.env_rcpt_to)),
            ),
            field("From", email.from.as_ref()),
            field("To", (!email.to.is_empty()).then(|| list(&email.to))),
            field("Cc", email.cc.as_deref().map(list)),
            subject,
            field("Message ID", email.message_id.as_deref().map(str::trim)),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The headers, a line each, as ace3's `<pre>` has them.
    pub fn headers(&self) -> Option<Clipped> {
        let email = self.analysis.email.as_ref()?;
        if email.headers.is_empty() {
            return None;
        }
        let mut text = String::new();
        for [name, value] in &email.headers {
            text.push_str(name);
            text.push_str(": ");
            text.push_str(value);
            text.push('\n');
            if text.len() > MAX_TEXT {
                break;
            }
        }
        Some(clip(&text, MAX_TEXT))
    }

    pub fn attachments(&self) -> Vec<Attachment> {
        let Some(email) = &self.analysis.email else {
            return Vec::new();
        };
        let log = &email.log_entry;
        let at = |list: &[String], i: usize| list.get(i).cloned().unwrap_or_default();
        log.attachment_names
            .iter()
            .take(MAX_ITEMS)
            .enumerate()
            .map(|(i, name)| Attachment {
                name: name.clone(),
                content_type: at(&log.attachment_types, i),
                size: log
                    .attachment_sizes
                    .get(i)
                    .map(u64::to_string)
                    .unwrap_or_default(),
                sha256: at(&log.attachment_hashes, i),
            })
            .collect()
    }

    pub fn more_attachments(&self) -> usize {
        self.analysis.email.as_ref().map_or(0, |email| {
            email
                .log_entry
                .attachment_names
                .len()
                .saturating_sub(MAX_ITEMS)
        })
    }
}

impl AnalysisView for EmailAnalysis {
    type View<'a> = EmailView<'a>;
    fn view(&self) -> EmailView<'_> {
        EmailView { analysis: self }
    }
}

// ---- yara: ace3's yara_analysis_v3_4.html ----

/// The most matches of one rule drawn with their marked hex dump, as ace3's `MAX_HIGHLIGHTED_MATCHES`.
pub const MAX_HIGHLIGHTED_MATCHES: usize = 100;
/// The most matches of one rule shown at all; ace3 shows every one.
pub const MAX_MATCHES: usize = 1000;
/// The most bytes of one matched value shown.
pub const MAX_MATCH_VALUE: usize = 1024;
/// The most bytes around a match drawn in its hex dump. The module keeps 64 either side by default.
pub const MAX_MATCH_CONTEXT: usize = 4096;
/// The most bytes of a stored dump shown for a match past `MAX_HIGHLIGHTED_MATCHES`: 64 bytes either side
/// of a short match is about 700.
pub const MAX_PLAIN_DUMP: usize = 2048;

/// `yara_scan_results`, from ace3's `yara_analysis_v3_4.html`: a panel a rule, with its target, meta and
/// tags, and its string matches under a summary that opens them. ace4's results have no rule source,
/// string patterns or disassembly, so those parts of ace3's view aren't here, and nor is its
/// `hide_intel` setting.
#[derive(Debug, Template)]
#[template(path = "analysis/yara_analysis_v3_4.html")]
pub struct YaraView<'a> {
    pub analysis: &'a YaraScanResults,
}

/// One string match as the view draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    pub offset: u64,
    pub identifier: String,
    pub value: Vec<Glyph>,
    /// How many bytes of the value were left out.
    pub more: usize,
    /// The marked hex dump, for the first `MAX_HIGHLIGHTED_MATCHES`.
    pub dump: Option<Vec<Vec<Segment>>>,
    /// The dump as the module wrote it, for the rest, as ace3 shows them.
    pub plain_dump: Option<Clipped>,
}

impl YaraView<'_> {
    /// The rule's meta as ace3's `meta_json` writes it, a line each.
    pub fn meta_lines(&self, result: &ScanResult) -> Vec<String> {
        json_text(&Value::Object(result.meta.clone()))
            .lines()
            .map(str::to_owned)
            .collect()
    }

    pub fn matches(&self, result: &ScanResult) -> Vec<YaraMatch> {
        result
            .context
            .iter()
            .take(MAX_MATCHES)
            .enumerate()
            .map(|(index, (offset, identifier, value, plain))| {
                let shown = &value[..value.len().min(MAX_MATCH_VALUE)];
                let highlighted = index < MAX_HIGHLIGHTED_MATCHES;
                let dump = result
                    .match_context
                    .get(index)
                    .filter(|_| highlighted)
                    .map(|context| {
                        let data = &context.data[..context.data.len().min(MAX_MATCH_CONTEXT)];
                        let start = usize::try_from(context.match_offset).unwrap_or(usize::MAX);
                        let length = usize::try_from(context.match_length).unwrap_or(0);
                        hexdump(data, start..start.saturating_add(length))
                    });
                YaraMatch {
                    offset: *offset,
                    identifier: identifier.clone(),
                    value: if highlighted {
                        visible(shown)
                    } else {
                        vec![Glyph::Text(shown.iter().map(|&b| char::from(b)).collect())]
                    },
                    more: value.len() - shown.len(),
                    plain_dump: dump.is_none().then(|| clip(plain, MAX_PLAIN_DUMP)),
                    dump,
                }
            })
            .collect()
    }

    pub fn more_matches(&self, result: &ScanResult) -> usize {
        result.context.len().saturating_sub(MAX_MATCHES)
    }
}

impl AnalysisView for YaraScanResults {
    type View<'a> = YaraView<'a>;
    fn view(&self) -> YaraView<'_> {
        YaraView { analysis: self }
    }
}

// ---- rdap: ace3's rdap.html ----

/// `rdap_analysis`, from ace3's `rdap.html`, which prints the details: each field by its key, and the
/// RDAP response under a summary that opens it.
#[derive(Debug, Template)]
#[template(path = "analysis/rdap.html")]
pub struct RdapView<'a> {
    pub analysis: &'a RdapAnalysis,
}

impl RdapView<'_> {
    pub fn fields(&self) -> Vec<Field> {
        let a = self.analysis;
        let names = |list: &Option<Vec<String>>| list.as_deref().map(list_text);
        [
            field("error", a.error.as_ref()),
            field("lookup_protocol", a.lookup_protocol.as_ref()),
            field("rdap_attempt_error", a.rdap_attempt_error.as_ref()),
            field("domain_name", a.domain_name.as_ref()),
            field("registrar", a.registrar.as_ref()),
            field("datetime_created", a.datetime_created.as_ref()),
            field("age_created_in_days", a.age_created_in_days.as_ref()),
            field(
                "datetime_of_last_update",
                a.datetime_of_last_update.as_ref(),
            ),
            field(
                "age_last_updated_in_days",
                a.age_last_updated_in_days.as_ref(),
            ),
            field("datetime_expiration", a.datetime_expiration.as_ref()),
            field("datetime_of_analysis", a.datetime_of_analysis.as_ref()),
            field("name_servers", names(&a.name_servers)),
            field("emails", names(&a.emails)),
            field("network_cidr", a.network_cidr.as_ref()),
            field("network_name", a.network_name.as_ref()),
            field("country", a.country.as_ref()),
            field("ip_version", a.ip_version),
            field("assignment_type", a.assignment_type.as_ref()),
            field("rdap_service_url", a.rdap_service_url.as_ref()),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub fn raw_json(&self) -> Option<Clipped> {
        let raw = self.analysis.rdap_raw_json.as_deref()?;
        let pretty = serde_json::from_str::<Value>(raw)
            .map(|value| json_text(&value))
            .unwrap_or_else(|_| raw.to_owned());
        Some(clip(&pretty, MAX_TEXT))
    }
}

fn list_text(items: &[String]) -> String {
    let shown = first(items, MAX_ITEMS);
    let mut text = list(shown.items);
    if shown.more > 0 {
        text.push_str(&format!(", and {} more", shown.more));
    }
    text
}

impl AnalysisView for RdapAnalysis {
    type View<'a> = RdapView<'a>;
    fn view(&self) -> RdapView<'_> {
        RdapView { analysis: self }
    }
}

// ---- dns: ace3's default_template.html ----

/// `fqdn_analysis`. ace3 prints its details with `default_template.html`; here each field by its key,
/// in the order ace3 writes them, with a list's entries joined.
#[derive(Debug, Template)]
#[template(path = "analysis/dns.html")]
pub struct FqdnView<'a> {
    pub analysis: &'a FqdnAnalysis,
}

impl FqdnView<'_> {
    pub fn fields(&self) -> Vec<Field> {
        let a = self.analysis;
        let names = |list: &[String]| (!list.is_empty()).then(|| list_text(list));
        [
            field("status", a.status.as_ref()),
            field("ip_address", a.ip_address.as_ref()),
            field("resolution_count", a.resolution_count),
            field("aliaslist", names(&a.aliaslist)),
            field("all_resolutions", names(&a.all_resolutions)),
            field(
                "mx",
                a.mx.as_deref().map(|mx| {
                    if mx.is_empty() {
                        "none".to_owned()
                    } else {
                        list_text(mx)
                    }
                }),
            ),
            field("wildcard_dns", a.wildcard_dns),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl AnalysisView for FqdnAnalysis {
    type View<'a> = FqdnView<'a>;
    fn view(&self) -> FqdnView<'_> {
        FqdnView { analysis: self }
    }
}

// ---- snort: ace3's default_template.html ----

/// `snort_signature_analysis`. ace3 prints its details with `default_template.html`: the signature's
/// id, and its rule.
#[derive(Debug, Template)]
#[template(path = "analysis/snort.html")]
pub struct SnortSignatureView<'a> {
    pub analysis: &'a SnortSignatureAnalysis,
}

impl SnortSignatureView<'_> {
    /// The rule, bounded as any block of text.
    pub fn signature(&self) -> Option<Clipped> {
        self.analysis
            .signature
            .as_deref()
            .map(|rule| clip(rule, MAX_TEXT))
    }
}

impl AnalysisView for SnortSignatureAnalysis {
    type View<'a> = SnortSignatureView<'a>;
    fn view(&self) -> SnortSignatureView<'_> {
        SnortSignatureView { analysis: self }
    }
}

// ---- conversation frequency: ace3's default_template.html ----

/// `email_conversation_frequency_analysis`. ace3 prints its details with `default_template.html`: the
/// two counts.
#[derive(Debug, Template)]
#[template(path = "analysis/conversation_frequency.html")]
pub struct ConversationFrequencyView<'a> {
    pub analysis: &'a EmailConversationFrequencyAnalysis,
}

impl ConversationFrequencyView<'_> {
    pub fn fields(&self) -> Vec<Field> {
        let a = self.analysis;
        [
            field("source_count", a.source_count),
            field("dest_count", a.dest_count),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl AnalysisView for EmailConversationFrequencyAnalysis {
    type View<'a> = ConversationFrequencyView<'a>;
    fn view(&self) -> ConversationFrequencyView<'_> {
        ConversationFrequencyView { analysis: self }
    }
}

// ---- newly registered domains: ace3's default_template.html ----

/// `nrd_analysis`. ace3 prints its details with `default_template.html`: the hit, when it was
/// found, and the registration RDAP gave or why there's none.
#[derive(Debug, Template)]
#[template(path = "analysis/nrd.html")]
pub struct NrdView<'a> {
    pub analysis: &'a NrdAnalysis,
}

impl NrdView<'_> {
    pub fn fields(&self) -> Vec<Field> {
        let a = self.analysis;
        [
            field("is_nrd", a.is_nrd),
            field("matched_at", a.matched_at.as_deref()),
            field("datetime_created", a.datetime_created.as_deref()),
            field("age_created_in_days", a.age_created_in_days.as_deref()),
            field("lookup_protocol", a.lookup_protocol.as_deref()),
            field("lookup_error", a.lookup_error.as_deref()),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl AnalysisView for NrdAnalysis {
    type View<'a> = NrdView<'a>;
    fn view(&self) -> NrdView<'_> {
        NrdView { analysis: self }
    }
}

// ---- user: ace3's user.html ----

/// Python's `str()` of a JSON value, as ace3's template prints one: a string as it is, a list as
/// its repr.
fn py_text(value: &Value) -> String {
    fn repr(value: &Value) -> String {
        match value {
            Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
            other => py_text(other),
        }
    }
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(_) => value.to_string(),
    }
}

/// A row of the user view, which links an address.
pub struct UserField {
    pub name: &'static str,
    pub value: String,
    pub mail: bool,
}

/// `user_analysis`, from ace3's `user.html`: the user's fields and the manager's, in ace3's order,
/// each only when the entry has it; the groups, each `memberOf` DN split into its `CN`, `OU` and
/// other parts and sorted by name; and the attributes, where ace3 prints them with `pprint`.
#[derive(Debug, Template)]
#[template(path = "analysis/user.html")]
pub struct UserView<'a> {
    pub analysis: &'a UserAnalysis,
}

/// The groups the view lists: name, organization and domain, or only the DN without entitlements.
pub type Group = (String, String, String);

/// The groups shown, at most `MAX_ITEMS`, and how many more there are.
pub struct Groups {
    pub items: Vec<Group>,
    pub more: usize,
}

impl UserView<'_> {
    pub fn fields(&self) -> Vec<UserField> {
        let mut rows = Vec::new();
        let mut add = |map: &serde_json::Map<String, Value>, key: &str, name: &'static str| {
            if let Some(value) = map.get(key) {
                rows.push(UserField {
                    name,
                    value: py_text(value),
                    mail: key == "mail",
                });
            }
        };
        if let Some(ldap) = &self.analysis.ldap {
            for (key, name) in [
                ("displayName", "Name"),
                ("mail", "Email"),
                ("company", "Company"),
                ("department", "Department"),
                ("division", "Division"),
                ("wWWHomePage", "Group"),
                ("title", "Title"),
                ("streetAddress", "Address"),
                ("l", "Location"),
                ("st", "State/Province"),
                ("co", "Country"),
                ("telephoneNumber", "Phone"),
                ("pwdLastSet", "Password Last Set"),
            ] {
                add(ldap, key, name);
            }
        }
        if let Some(Some(manager)) = &self.analysis.manager_ldap {
            for (key, name) in [
                ("displayName", "Manager"),
                ("mail", "Manager Email"),
                ("telephoneNumber", "Manager Phone"),
            ] {
                add(manager, key, name);
            }
        }
        rows
    }

    pub fn has_entitlements(&self) -> bool {
        self.analysis
            .ldap
            .as_ref()
            .is_some_and(|l| l.contains_key("entitlements"))
    }

    pub fn groups(&self) -> Groups {
        let Some(ldap) = &self.analysis.ldap else {
            return Groups {
                items: Vec::new(),
                more: 0,
            };
        };
        let mut groups: Vec<Group> =
            if let Some(Value::Array(entitlements)) = ldap.get("entitlements") {
                entitlements
                    .iter()
                    .map(|e| {
                        let dn = e["group"]
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| py_text(&e["group"]));
                        let (mut name, mut org, mut domain) = (Vec::new(), Vec::new(), Vec::new());
                        for part in dn.split(',') {
                            let rest = part.get(3..).unwrap_or_default().to_owned();
                            if part.starts_with("CN=") {
                                name.push(rest);
                            } else if part.starts_with("OU=") {
                                org.push(rest);
                            } else {
                                domain.push(rest);
                            }
                        }
                        (name.join("."), org.join("."), domain.join("."))
                    })
                    .collect()
            } else if let Some(Value::Array(member_of)) = ldap.get("memberOf") {
                member_of
                    .iter()
                    .map(|g| (py_text(g), String::new(), String::new()))
                    .collect()
            } else {
                Vec::new()
            };
        if self.has_entitlements() {
            // Jinja's sort ignores case by default
            groups.sort_by_key(|g| g.0.to_lowercase());
        }
        let more = groups.len().saturating_sub(MAX_ITEMS);
        groups.truncate(MAX_ITEMS);
        Groups {
            items: groups,
            more,
        }
    }

    pub fn attributes(&self) -> Option<Clipped> {
        let ldap = self.analysis.ldap.as_ref()?;
        let value = sort_json_keys(Value::Object(ldap.clone()));
        let text = serde_json::to_string_pretty(&value).ok()?;
        Some(clip(&text, MAX_TEXT))
    }
}

impl AnalysisView for UserAnalysis {
    type View<'a> = UserView<'a>;
    fn view(&self) -> UserView<'_> {
        UserView { analysis: self }
    }
}

// ---- email thread: ace3's email_thread.html ----

/// `email_thread_analysis`, from ace3's `email_thread.html`: how the conversation was assembled, the
/// findings ace3 adds as a summary detail, each look-alike pair, the timeline and what the record
/// is missing. ace3 colours its badges with Bootstrap; here they're words in the same places.
#[derive(Debug, Template)]
#[template(path = "analysis/email_thread.html")]
pub struct EmailThreadView<'a> {
    pub analysis: &'a EmailThreadAnalysis,
}

impl EmailThreadView<'_> {
    pub fn findings(&self) -> Option<String> {
        self.analysis.findings()
    }

    pub fn lookalikes(&self) -> Shown<'_, Lookalike> {
        first(&self.analysis.lookalikes, MAX_ITEMS)
    }

    pub fn messages(&self) -> Shown<'_, ThreadMessage> {
        first(&self.analysis.messages, MAX_ITEMS)
    }

    /// Every joined thread gave one message: what a subject collision looks like.
    pub fn one_each(&self) -> bool {
        self.analysis.thread_message_counts.iter().max() == Some(&1)
    }

    pub fn counts(&self) -> String {
        let counts: Vec<String> = self
            .analysis
            .thread_message_counts
            .iter()
            .map(u32::to_string)
            .collect();
        counts.join(", ")
    }

    /// ace3's `'%.4f' | format(jaro_winkler)`.
    pub fn similarity(&self, entry: &Lookalike) -> String {
        format!("{:.4}", entry.jaro_winkler)
    }

    pub fn plural(&self, count: usize) -> &'static str {
        if count == 1 { "" } else { "s" }
    }
}

impl AnalysisView for EmailThreadAnalysis {
    type View<'a> = EmailThreadView<'a>;
    fn view(&self) -> EmailThreadView<'_> {
        EmailThreadView { analysis: self }
    }
}

// ---- splunk: ace3's api_analysis.html ----

/// The most bytes of one cell of a Splunk result shown.
pub const MAX_CELL: usize = 1024;

/// `splunk_api_analysis`, from ace3's `api_analysis.html`: the question and summary, an error, the
/// query under a summary that opens it, the rows as a table, and the raw details. ace3's table sorts
/// and resizes its columns with an inline jQuery script, which the page's policy refuses, so this one
/// doesn't; and ace4's results have no `gui_link` yet.
#[derive(Debug, Template)]
#[template(path = "analysis/api_analysis.html")]
pub struct SplunkView<'a> {
    pub analysis: &'a SplunkApiAnalysis,
}

/// The results as a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub more: usize,
}

impl SplunkView<'_> {
    /// The rows in the query's `| table` columns, else the first row's, as ace3's.
    pub fn table(&self) -> Option<Table> {
        let rows = self.analysis.query_results.as_deref()?;
        let first_row = rows.first()?;
        let columns: Vec<String> = match &self.analysis.table_columns {
            Some(columns) => columns.clone(),
            None => first_row.keys().cloned().collect(),
        };
        let shown = first(rows, MAX_ITEMS);
        Some(Table {
            rows: shown
                .items
                .iter()
                .map(|row| {
                    columns
                        .iter()
                        .map(|column| clip(&cell(row.get(column)), MAX_CELL).text)
                        .collect()
                })
                .collect(),
            columns,
            more: shown.more,
        })
    }

    pub fn query(&self) -> Option<Clipped> {
        self.analysis.query.as_deref().map(|q| clip(q, MAX_TEXT))
    }

    pub fn raw(&self) -> Clipped {
        let json = serde_json::to_value(self.analysis).unwrap_or_default();
        clip(&json_text(&json), MAX_JSON)
    }
}

/// A cell as text: a string as it is, a multivalue field's strings a line each.
fn cell(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| cell(Some(item)))
            .collect::<Vec<_>>()
            .join("\n"),
        Some(other) => other.to_string(),
    }
}

impl AnalysisView for SplunkApiAnalysis {
    type View<'a> = SplunkView<'a>;
    fn view(&self) -> SplunkView<'_> {
        SplunkView { analysis: self }
    }
}

// ---- clicker detection: ace3's api_analysis.html ----

/// One click as the view lists it: its time, user, action, the URL it reached, and the search.
pub type Click = (String, String, String, String, String);

/// The clicks shown, at most `MAX_ITEMS`, and how many more there are.
pub struct Clicks {
    pub items: Vec<Click>,
    pub more: usize,
}

/// `splunk_clicker_detection_analysis`, which ace3 draws with `api_analysis.html`: the link to the
/// last search, the question, an error and the raw details, with the clicks, which ace3 lists in the
/// alert's URL Clicks panel.
#[derive(Debug, Template)]
#[template(path = "analysis/clicker.html")]
pub struct ClickerView<'a> {
    pub analysis: &'a SplunkClickerDetectionAnalysis,
}

impl ClickerView<'_> {
    /// The link, when it's an HTTPS one, as the module makes it.
    pub fn link(&self) -> Option<&str> {
        self.analysis
            .gui_link
            .as_deref()
            .filter(|l| l.starts_with("https://"))
    }

    pub fn link_label(&self) -> &str {
        self.analysis
            .gui_link_label
            .as_deref()
            .unwrap_or("Open Search")
    }

    pub fn clicks(&self) -> Clicks {
        let events = self.analysis.clicker_events.as_deref().unwrap_or_default();
        let items: Vec<Click> = events
            .iter()
            .take(MAX_ITEMS)
            .map(|e| {
                (
                    cell(Some(&e.timestamp)),
                    cell(Some(&e.user)),
                    cell(Some(&e.action_type)),
                    cell(Some(&e.url)),
                    e.source.clone(),
                )
            })
            .collect();
        Clicks {
            more: events.len() - items.len(),
            items,
        }
    }

    pub fn raw(&self) -> Clipped {
        let json = serde_json::to_value(self.analysis).unwrap_or_default();
        clip(&json_text(&json), MAX_JSON)
    }
}

impl AnalysisView for SplunkClickerDetectionAnalysis {
    type View<'a> = ClickerView<'a>;
    fn view(&self) -> ClickerView<'_> {
        ClickerView { analysis: self }
    }
}

// ---- the types ace3 draws with default_template.html ----

/// `archive_analysis`: ace3 prints its details, the count and the files.
#[derive(Debug, Template)]
#[template(path = "analysis/archive.html")]
pub struct ArchiveView<'a> {
    pub analysis: &'a ArchiveAnalysis,
}

impl ArchiveView<'_> {
    pub fn files(&self) -> Shown<'_, String> {
        first(&self.analysis.extracted_files, MAX_ITEMS)
    }
}

impl AnalysisView for ArchiveAnalysis {
    type View<'a> = ArchiveView<'a>;
    fn view(&self) -> ArchiveView<'_> {
        ArchiveView { analysis: self }
    }
}

/// The most macros whose code the olevba view shows. Each macro is also a file the module added.
pub const MAX_MACROS: usize = 32;

/// `olevba_analysis`: the file's kind, oletools' keyword counts, and each macro with its code.
#[derive(Debug, Template)]
#[template(path = "analysis/olevba.html")]
pub struct OlevbaView<'a> {
    pub analysis: &'a OlevbaAnalysis,
}

/// One macro as the view draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroView {
    pub file_name: Option<String>,
    pub stream_path: String,
    pub vba_filename: String,
    pub local_path: String,
    pub code: Clipped,
}

impl OlevbaView<'_> {
    pub fn macros(&self) -> Vec<MacroView> {
        self.analysis
            .macros
            .iter()
            .take(MAX_MACROS)
            .map(|m: &OlevbaMacro| MacroView {
                file_name: m.file_name.as_ref().map(text_of),
                stream_path: text_of(&m.stream_path),
                vba_filename: text_of(&m.vba_filename),
                local_path: m.local_path.to_string(),
                code: clip(&m.vba_code, MAX_TEXT),
            })
            .collect()
    }

    pub fn more_macros(&self) -> usize {
        self.analysis.macros.len().saturating_sub(MAX_MACROS)
    }
}

impl AnalysisView for OlevbaAnalysis {
    type View<'a> = OlevbaView<'a>;
    fn view(&self) -> OlevbaView<'_> {
        OlevbaView { analysis: self }
    }
}

/// `rtf_ole_object_analysis`: rtfobj's exit code, the objects it saved, and its report.
#[derive(Debug, Template)]
#[template(path = "analysis/rtf.html")]
pub struct RtfView<'a> {
    pub analysis: &'a RtfOleObjectAnalysis,
}

impl RtfView<'_> {
    pub fn files(&self) -> Shown<'_, String> {
        first(&self.analysis.extracted_files, MAX_ITEMS)
    }

    pub fn stdout(&self) -> Clipped {
        clip(&self.analysis.stdout, MAX_TEXT)
    }

    pub fn stderr(&self) -> Clipped {
        clip(&self.analysis.stderr, MAX_TEXT)
    }
}

impl AnalysisView for RtfOleObjectAnalysis {
    type View<'a> = RtfView<'a>;
    fn view(&self) -> RtfView<'_> {
        RtfView { analysis: self }
    }
}

/// `msoffice_encryption_analysis`: the password that opened it or why not, the passwords tried, and
/// the email body they came from.
#[derive(Debug, Template)]
#[template(path = "analysis/msoffice.html")]
pub struct MsofficeView<'a> {
    pub analysis: &'a MsofficeEncryptionAnalysis,
}

impl MsofficeView<'_> {
    pub fn words(&self) -> Shown<'_, String> {
        first(&self.analysis.word_list, MAX_ITEMS)
    }

    pub fn body(&self) -> Option<Clipped> {
        self.analysis
            .email_body
            .as_deref()
            .map(|body| clip(body, MAX_TEXT))
    }
}

impl AnalysisView for MsofficeEncryptionAnalysis {
    type View<'a> = MsofficeView<'a>;
    fn view(&self) -> MsofficeView<'_> {
        MsofficeView { analysis: self }
    }
}

/// `xlm_deobfuscator_analysis`: the cells the deobfuscator listed.
#[derive(Debug, Template)]
#[template(path = "analysis/xlm.html")]
pub struct XlmView<'a> {
    pub analysis: &'a XlmDeobfuscatorAnalysis,
}

impl AnalysisView for XlmDeobfuscatorAnalysis {
    type View<'a> = XlmView<'a>;
    fn view(&self) -> XlmView<'_> {
        XlmView { analysis: self }
    }
}

/// `pcode_analysis`: the lines of the disassembly, which is a file the module added.
#[derive(Debug, Template)]
#[template(path = "analysis/pcode.html")]
pub struct PCodeView<'a> {
    pub analysis: &'a PCodeAnalysis,
}

impl AnalysisView for PCodeAnalysis {
    type View<'a> = PCodeView<'a>;
    fn view(&self) -> PCodeView<'_> {
        PCodeView { analysis: self }
    }
}

/// `pdf_analysis`: the encryption of a PDF that opens with no password, and what it allows.
#[derive(Debug, Template)]
#[template(path = "analysis/pdf.html")]
pub struct PdfView<'a> {
    pub analysis: &'a PdfAnalysis,
}

impl PdfView<'_> {
    pub fn permissions(&self) -> Vec<(&'static str, bool)> {
        let Some(encryption) = &self.analysis.encryption else {
            return Vec::new();
        };
        let p = &encryption.permissions;
        vec![
            ("accessibility", p.accessibility),
            ("extract", p.extract),
            ("modify_annotation", p.modify_annotation),
            ("modify_assembly", p.modify_assembly),
            ("modify_form", p.modify_form),
            ("modify_other", p.modify_other),
            ("print_lowres", p.print_lowres),
            ("print_highres", p.print_highres),
        ]
    }
}

impl AnalysisView for PdfAnalysis {
    type View<'a> = PdfView<'a>;
    fn view(&self) -> PdfView<'_> {
        PdfView { analysis: self }
    }
}
