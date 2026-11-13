//! The filters of a list screen (PLAN.md 5.10), ace3's `saq/gui/filter_query.py`, `filter_entry.py`,
//! `filter_names.py`, `filter_screens.py` and `filter_url.py`: one model the GUI and the JSON API both use.
//!
//! A filter list is ace3's `[{name, inverted, values}]`: entries are ANDed, the values of one entry are
//! ORed, and an inverted entry matches exactly what the entry doesn't, an alert with no value at all
//! included. Entries with the same name and polarity are merged first, as ace3's `resolve_filter_list` merges
//! them, so two `queue` entries mean either queue. A share link carries the list as repeated `f` values,
//! `[!]<slug>:<v1>,<v2>`, in ace3's encoding (`encode`, `decode`), and its slugs are ace3's, which ace3
//! calls a permanent contract, so an ace3 link's filters mean the same here.
//!
//! `check` is the one gate for a filter list, whichever door it came through: a share link, the GUI's
//! editor, an API call or a saved filter. It refuses an unknown name, a value of the wrong shape and a list
//! past the bounds below, and returns the list in its canonical spelling, which is what a saved filter
//! stores. The SQL is in `alerts` and `detection_points`: each filter is a fixed condition in one static
//! query, checked against the schema when it's built, and every value reaches it as a bound parameter. There
//! is no SQL built from text.
//!
//! What's left out of ace3's filters, and the step that brings the field each one reads, is
//! `FilterScreen::left_out`. ace3's alert filters also take `$USER` and `$USER_QUEUE`, which stand for the
//! viewer in a stored filter; they only have meaning for the owner and queue filters, so they come with them.
//!
//! ace3's event list isn't a filter screen, as it has no saved filters or share links: its filters are
//! `events`, under the same rules (5.11's events area).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

use crate::ServiceError;
use crate::permission::{ALERT_READ, FILE_COLLECTION_READ, PermissionName, REMEDIATION_READ};

mod dates;
pub mod events;

/// The most entries a filter list holds, once merged.
pub const MAX_FILTER_ENTRIES: usize = 32;
/// The most values one entry holds.
pub const MAX_FILTER_VALUES: usize = 64;
/// The longest value, in characters. A text search can't be longer, so its cost has a bound.
pub const MAX_FILTER_VALUE_CHARS: usize = 256;

/// ace3's disposition names, from its `saq.default.yaml`, which the disposition filter offers. A site's own
/// are taken too, since ace4 doesn't configure them yet (`Service::disposition`).
pub const DISPOSITIONS: &[&str] = &[
    "OPEN",
    "FALSE_POSITIVE",
    "IGNORE",
    "UNKNOWN",
    "REVIEWED",
    "GRAYWARE",
    "POLICY_VIOLATION",
    "RECONNAISSANCE",
    "WEAPONIZATION",
    "DELIVERY",
    "EXPLOITATION",
    "INSTALLATION",
    "COMMAND_AND_CONTROL",
    "EXFIL",
    "DAMAGE",
];

/// ace3's signature families (`SignatureType`), which the detection points screen's `family` takes.
pub const SIGNATURE_FAMILIES: &[&str] = &["yara", "hunt", "observable_modifier", "builtin"];

/// The observable filter's type that matches any type.
pub const ANY_TYPE: &str = "Any";

/// A screen whose list has filters, saved filters and share links: ace3's `FilterScreen`. Four of ace3's
/// eleven exist here; the SVS screens come with SVS (7.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FilterScreen {
    /// The alert list.
    Alerts,
    /// Every alert's detections (5.6's `detection_points`).
    DetectionPoints,
    /// The remediations (PLAN.md 7.9), ace3's `REMEDIATIONS_SCREEN`.
    Remediations,
    /// The file collections (PLAN.md 7.9), ace3's `FILE_COLLECTIONS_SCREEN`.
    FileCollections,
}

/// How an editor edits one filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    /// Free text, one or more values.
    Text,
    /// One or more of `options`, or another value of the same shape.
    Multi,
    /// A date range (`dates`).
    DateRange,
    /// `[type, value]` pairs, the observable filter.
    Pair,
}

impl FilterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FilterKind::Text => "text",
            FilterKind::Multi => "multi",
            FilterKind::DateRange => "date_range",
            FilterKind::Pair => "pair",
        }
    }
}

/// One filter a screen has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterSpec {
    /// Its name in a filter entry, ace3's display name.
    pub name: &'static str,
    /// Its name in a share link: ace3's, and never to change.
    pub slug: &'static str,
    pub kind: FilterKind,
    /// The values a `Multi` filter offers.
    pub options: &'static [&'static str],
    /// What a value looks like, for an editor's placeholder.
    pub hint: &'static str,
}

/// One of ace3's filters that this screen doesn't have yet, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeftOut {
    pub name: &'static str,
    pub slug: &'static str,
    pub why: &'static str,
}

const fn spec(
    name: &'static str,
    slug: &'static str,
    kind: FilterKind,
    options: &'static [&'static str],
    hint: &'static str,
) -> FilterSpec {
    FilterSpec {
        name,
        slug,
        kind,
        options,
        hint,
    }
}

/// The alert list's filters, in name order, as ace3 lists them.
const ALERT_FILTERS: &[FilterSpec] = &[
    spec(
        "Alert Date",
        "alert_date",
        FilterKind::DateRange,
        &[],
        "-7d, or MM-DD-YYYY HH:MM - MM-DD-YYYY HH:MM",
    ),
    spec(
        "Analysis",
        "analysis",
        FilterKind::Multi,
        &[],
        "a module's name, such as rdap_analyzer",
    ),
    spec(
        "Description",
        "description",
        FilterKind::Text,
        &[],
        "text the alert's title contains",
    ),
    spec(
        "Detection Point",
        "detection_point",
        FilterKind::Text,
        &[],
        "signature-uuid[:version]",
    ),
    spec(
        "Disposition",
        "disposition",
        FilterKind::Multi,
        DISPOSITIONS,
        "OPEN, FALSE_POSITIVE, ...",
    ),
    spec(
        "Disposition By",
        "disposition_by",
        FilterKind::Text,
        &[],
        "a user's or key's name, or None",
    ),
    spec(
        "Disposition Date",
        "disposition_date",
        FilterKind::DateRange,
        &[],
        "-7d, or MM-DD-YYYY HH:MM - MM-DD-YYYY HH:MM",
    ),
    spec(
        "Event Date",
        "event_date",
        FilterKind::DateRange,
        &[],
        "-7d, or MM-DD-YYYY HH:MM - MM-DD-YYYY HH:MM",
    ),
    spec(
        "Observable",
        "observable",
        FilterKind::Pair,
        &[],
        "a type, or Any, and a value",
    ),
    spec(
        "Tag",
        "tag",
        FilterKind::Text,
        &[],
        "a tag, with * matching anything",
    ),
    spec(
        "Unconfirmed Detections",
        "unconfirmed_detections",
        FilterKind::Multi,
        UNCONFIRMED_DETECTIONS,
        "True",
    ),
];

const ALERT_LEFT_OUT: &[LeftOut] = &[
    LeftOut {
        name: "Alert Type",
        slug: "alert_type",
        why: "a root has no alert type yet: 6.1's collector submits the first, as mailbox",
    },
    LeftOut {
        name: "Owner",
        slug: "owner",
        why: "an alert has no owner yet, and no step in PLAN.md adds one",
    },
    LeftOut {
        name: "Queue",
        slug: "queue",
        why: "an alert has no queue until alert routing (7.13)",
    },
    LeftOut {
        name: "Reviewed",
        slug: "reviewed",
        why: "a disposition has no review yet, and no step in PLAN.md adds one",
    },
];

/// The Unconfirmed Detections filter's values, ace3's `UNCONFIRMED_DETECTIONS_OPTIONS`.
pub const UNCONFIRMED_DETECTIONS: &[&str] = &["True", "False"];
/// The Verdict filter's values: a verdict, or `none` for a detection with none (PLAN.md 7.14).
pub const VERDICT_VALUES: &[&str] = &["tp", "fp", "none"];
/// The Source filter's values.
pub const VERDICT_SOURCES: &[&str] = &["explicit", "inherited_single", "inherited_multi"];
/// The Has Override filter's values.
pub const BOOLEANS: &[&str] = &["true", "false"];

/// The detection points screen's filters, ace3's `DETECTION_POINTS_SCREEN`.
const DETECTION_POINT_FILTERS: &[FilterSpec] = &[
    spec(
        "Alert Date",
        "alert_date",
        FilterKind::DateRange,
        &[],
        "-7d, or MM-DD-YYYY HH:MM - MM-DD-YYYY HH:MM",
    ),
    spec(
        "Family",
        "family",
        FilterKind::Multi,
        SIGNATURE_FAMILIES,
        "yara",
    ),
    spec(
        "Signature",
        "signature",
        FilterKind::Text,
        &[],
        "signature-uuid[:version]",
    ),
    spec(
        "Verdict",
        "verdict",
        FilterKind::Multi,
        VERDICT_VALUES,
        "tp, fp, or none",
    ),
    spec(
        "Source",
        "source",
        FilterKind::Multi,
        VERDICT_SOURCES,
        "explicit",
    ),
    spec(
        "Has Override",
        "has_override",
        FilterKind::Multi,
        BOOLEANS,
        "true",
    ),
];

const DETECTION_POINT_LEFT_OUT: &[LeftOut] = &[LeftOut {
    name: "Queue",
    slug: "queue",
    why: "ace3 filters on the alert's queue, which comes with alert routing (7.13)",
}];

/// ace3's remediation actions, statuses and remediator results, which the remediations screen offers.
pub const REMEDIATION_ACTIONS: &[&str] = &["remove", "restore"];
pub const ACTION_STATUSES: &[&str] = &["NEW", "IN_PROGRESS", "COMPLETED"];
pub const REMEDIATION_RESULTS: &[&str] = &[
    "DELAYED",
    "ERROR",
    "FAILED",
    "IGNORE",
    "SUCCESS",
    "CANCELLED",
    "NOT_FOUND",
];
/// ace3's file collector results.
pub const COLLECTION_RESULTS: &[&str] = &[
    "DELAYED",
    "ERROR",
    "FAILED",
    "SUCCESS",
    "CANCELLED",
    "HOST_OFFLINE",
    "FILE_NOT_FOUND",
];

const CREATED_HINT: &str = "-7d, or MM-DD-YYYY HH:MM - MM-DD-YYYY HH:MM";

/// The remediations screen's filters, ace3's `REMEDIATIONS_SCREEN`, in its order.
const REMEDIATION_FILTERS: &[FilterSpec] = &[
    spec("ID", "id", FilterKind::Text, &[], "a remediation's id"),
    spec(
        "Remediator",
        "remediator",
        FilterKind::Text,
        &[],
        "text the remediator's name contains",
    ),
    spec(
        "Type",
        "type",
        FilterKind::Text,
        &[],
        "text the observable type contains",
    ),
    spec(
        "Value",
        "value",
        FilterKind::Text,
        &[],
        "text the value contains",
    ),
    spec(
        "Analyst",
        "analyst",
        FilterKind::Text,
        &[],
        "text the analyst's name contains",
    ),
    spec(
        "Action",
        "action",
        FilterKind::Multi,
        REMEDIATION_ACTIONS,
        "remove",
    ),
    spec(
        "Status",
        "status",
        FilterKind::Multi,
        ACTION_STATUSES,
        "COMPLETED",
    ),
    spec(
        "Result",
        "result",
        FilterKind::Multi,
        REMEDIATION_RESULTS,
        "SUCCESS",
    ),
    spec(
        "Created",
        "created",
        FilterKind::DateRange,
        &[],
        CREATED_HINT,
    ),
];

/// The file collections screen's filters, ace3's `FILE_COLLECTIONS_SCREEN`, in its order.
const FILE_COLLECTION_FILTERS: &[FilterSpec] = &[
    spec("ID", "id", FilterKind::Text, &[], "a collection's id"),
    spec(
        "Collector",
        "collector",
        FilterKind::Text,
        &[],
        "text the collector's name contains",
    ),
    spec(
        "Type",
        "type",
        FilterKind::Text,
        &[],
        "text the observable type contains",
    ),
    spec(
        "Value",
        "value",
        FilterKind::Text,
        &[],
        "text the value contains",
    ),
    spec("Alert", "alert", FilterKind::Text, &[], "an alert's id"),
    spec(
        "Status",
        "status",
        FilterKind::Multi,
        ACTION_STATUSES,
        "COMPLETED",
    ),
    spec(
        "Result",
        "result",
        FilterKind::Multi,
        COLLECTION_RESULTS,
        "SUCCESS",
    ),
    spec(
        "Created",
        "created",
        FilterKind::DateRange,
        &[],
        CREATED_HINT,
    ),
];

impl FilterScreen {
    pub const ALL: &'static [FilterScreen] = &[
        FilterScreen::Alerts,
        FilterScreen::DetectionPoints,
        FilterScreen::Remediations,
        FilterScreen::FileCollections,
    ];

    /// Its name, ace3's `saved_filters.screen`.
    pub fn name(self) -> &'static str {
        match self {
            FilterScreen::Alerts => "alerts",
            FilterScreen::DetectionPoints => "detection_points",
            FilterScreen::Remediations => "remediations",
            FilterScreen::FileCollections => "file_collections",
        }
    }

    pub fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|screen| screen.name() == name)
    }

    /// The permission that reads the screen's data, which its saved filters and its descriptor need too, as
    /// in ace3: a saved filter holds nothing its owner couldn't type into the filter bar.
    pub fn permission(self) -> PermissionName {
        match self {
            FilterScreen::Alerts | FilterScreen::DetectionPoints => ALERT_READ,
            FilterScreen::Remediations => REMEDIATION_READ,
            FilterScreen::FileCollections => FILE_COLLECTION_READ,
        }
    }

    pub fn filters(self) -> &'static [FilterSpec] {
        match self {
            FilterScreen::Alerts => ALERT_FILTERS,
            FilterScreen::DetectionPoints => DETECTION_POINT_FILTERS,
            FilterScreen::Remediations => REMEDIATION_FILTERS,
            FilterScreen::FileCollections => FILE_COLLECTION_FILTERS,
        }
    }

    /// ace3's filters of this screen that aren't here, each with why.
    pub fn left_out(self) -> &'static [LeftOut] {
        match self {
            FilterScreen::Alerts => ALERT_LEFT_OUT,
            FilterScreen::DetectionPoints => DETECTION_POINT_LEFT_OUT,
            FilterScreen::Remediations | FilterScreen::FileCollections => &[],
        }
    }

    pub fn spec(self, name: &str) -> Option<&'static FilterSpec> {
        self.filters().iter().find(|spec| spec.name == name)
    }

    fn by_slug(self, slug: &str) -> Option<&'static FilterSpec> {
        self.filters().iter().find(|spec| spec.slug == slug)
    }
}

impl std::fmt::Display for FilterScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One value of an entry: text, or for the observable filter a `[type, value]` pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    Text(String),
    Pair(String, String),
}

impl FilterValue {
    fn texts(&self) -> impl Iterator<Item = &str> {
        let (a, b) = match self {
            FilterValue::Text(text) => (text.as_str(), None),
            FilterValue::Pair(kind, value) => (kind.as_str(), Some(value.as_str())),
        };
        std::iter::once(a).chain(b)
    }
}

/// One entry of a filter list, ace3's `FilterEntryBase`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterEntry {
    /// A filter's name on its screen, such as `Disposition`.
    pub name: String,
    #[serde(default)]
    pub inverted: bool,
    pub values: Vec<FilterValue>,
}

impl FilterEntry {
    pub fn new(name: &str, inverted: bool, values: Vec<FilterValue>) -> Self {
        FilterEntry {
            name: name.to_owned(),
            inverted,
            values,
        }
    }

    pub fn text(name: &str, inverted: bool, values: &[&str]) -> Self {
        FilterEntry::new(
            name,
            inverted,
            values
                .iter()
                .map(|value| FilterValue::Text((*value).to_owned()))
                .collect(),
        )
    }
}

fn invalid(message: impl Into<String>) -> ServiceError {
    ServiceError::InvalidRequest(message.into())
}

/// Entries with the same name and polarity as one, in the order each first appears.
fn merged(entries: &[FilterEntry]) -> Vec<FilterEntry> {
    let mut out: Vec<FilterEntry> = Vec::new();
    for entry in entries {
        match out
            .iter_mut()
            .find(|seen| seen.name == entry.name && seen.inverted == entry.inverted)
        {
            Some(seen) => seen.values.extend(entry.values.iter().cloned()),
            None => out.push(entry.clone()),
        }
    }
    out
}

/// A filter list checked for a screen and spelt canonically: entries merged, each value of its filter's
/// shape and normalized (a signature's uuid and a file's sha256 lowercased, an observable's type as its
/// type's name), repeated values dropped, and the bounds held. A value the filter can't take is
/// `InvalidRequest` saying which.
pub fn check(
    screen: FilterScreen,
    entries: &[FilterEntry],
) -> Result<Vec<FilterEntry>, ServiceError> {
    let entries = merged(entries);
    if entries.len() > MAX_FILTER_ENTRIES {
        return Err(invalid(format!(
            "a filter list has at most {MAX_FILTER_ENTRIES} filters"
        )));
    }
    let now = Utc::now();
    entries
        .into_iter()
        .map(|entry| {
            let Some(spec) = screen.spec(&entry.name) else {
                return Err(
                    match screen
                        .left_out()
                        .iter()
                        .find(|gone| gone.name == entry.name)
                    {
                        Some(gone) => invalid(format!(
                            "the {} filter isn't here yet: {}",
                            gone.name, gone.why
                        )),
                        None => invalid(format!(
                            "the {screen} screen has no filter named {:?}",
                            entry.name
                        )),
                    },
                );
            };
            if entry.values.is_empty() || entry.values.len() > MAX_FILTER_VALUES {
                return Err(invalid(format!(
                    "a {} filter has 1 to {MAX_FILTER_VALUES} values",
                    spec.name
                )));
            }
            let mut values: Vec<FilterValue> = Vec::with_capacity(entry.values.len());
            for value in &entry.values {
                for text in value.texts() {
                    if text.chars().count() > MAX_FILTER_VALUE_CHARS {
                        return Err(invalid(format!(
                            "a {} value is at most {MAX_FILTER_VALUE_CHARS} characters",
                            spec.name
                        )));
                    }
                    if text.chars().any(char::is_control) {
                        return Err(invalid(format!(
                            "a {} value can't hold a control character",
                            spec.name
                        )));
                    }
                }
                let value = canonical(spec, value, now)?;
                if !values.contains(&value) {
                    values.push(value);
                }
            }
            Ok(FilterEntry {
                name: spec.name.to_owned(),
                inverted: entry.inverted,
                values,
            })
        })
        .collect()
}

/// A value of `spec`'s filter in its canonical spelling, or why it isn't one.
fn canonical(
    spec: &FilterSpec,
    value: &FilterValue,
    now: DateTime<Utc>,
) -> Result<FilterValue, ServiceError> {
    let name = spec.name;
    let text = match (spec.kind, value) {
        (FilterKind::Pair, FilterValue::Pair(kind, value)) => {
            return observable_pair(kind, value)
                .map(|(kind, value)| FilterValue::Pair(kind, value));
        }
        (FilterKind::Pair, FilterValue::Text(_)) => {
            return Err(invalid(format!("an {name} value is a [type, value] pair")));
        }
        (_, FilterValue::Pair(..)) => {
            return Err(invalid(format!("a {name} value is text, not a pair")));
        }
        (_, FilterValue::Text(text)) => text,
    };
    if text.is_empty() {
        // ace3: an empty text value would match everything
        return Err(invalid(format!("a {name} value can't be empty")));
    }
    let text = match (spec.slug, spec.kind) {
        (_, FilterKind::DateRange) => {
            dates::window(text, now, Tz::UTC).map_err(|why| invalid(format!("{name}: {why}")))?;
            text.clone()
        }
        ("detection_point" | "signature", _) => signature_value(text)
            .map(|(uuid, version)| match version {
                Some(version) => format!("{uuid}:{version}"),
                None => uuid,
            })
            .map_err(|why| invalid(format!("{name}: {why}")))?,
        ("disposition", _) => {
            if !is_disposition(text) {
                return Err(invalid(format!(
                    "{name}: {text:?} isn't a disposition, which is up to 64 of A-Z, 0-9 and _"
                )));
            }
            text.clone()
        }
        ("analysis", _) => {
            if !is_module_name(text) {
                return Err(invalid(format!(
                    "{name}: {text:?} isn't a module's name, which is a-z, 0-9 and _"
                )));
            }
            text.clone()
        }
        ("id", _) => {
            let id: i64 = text
                .trim()
                .parse()
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| invalid(format!("{name}: {text:?} isn't an id")))?;
            id.to_string()
        }
        ("alert", _) => text
            .trim()
            .parse::<uuid::Uuid>()
            .map(|uuid| uuid.to_string())
            .map_err(|_| invalid(format!("{name}: {text:?} isn't an alert's id")))?,
        ("family", _) => {
            let family = text.to_ascii_lowercase();
            if !SIGNATURE_FAMILIES.contains(&family.as_str()) {
                return Err(invalid(format!(
                    "{name}: {text:?} isn't one of {}",
                    SIGNATURE_FAMILIES.join(", ")
                )));
            }
            family
        }
        (_, FilterKind::Multi) if !spec.options.is_empty() => spec
            .options
            .iter()
            .find(|option| option.eq_ignore_ascii_case(text))
            .map(|option| (*option).to_owned())
            .ok_or_else(|| {
                invalid(format!(
                    "{name}: {text:?} isn't one of {}",
                    spec.options.join(", ")
                ))
            })?,
        _ => text.clone(),
    };
    Ok(FilterValue::Text(text))
}

fn is_disposition(text: &str) -> bool {
    text.len() <= 64
        && text.starts_with(|c: char| c.is_ascii_uppercase())
        && text
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn is_module_name(text: &str) -> bool {
    text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// ace3's `parse_detection_point_value`: a signature's uuid, lowercased, and its version after the first
/// colon, matched exactly; no version means any.
fn signature_value(text: &str) -> Result<(String, Option<String>), String> {
    let (uuid, version) = match text.trim().split_once(':') {
        Some((uuid, version)) => (uuid, Some(version)),
        None => (text.trim(), None),
    };
    let shaped = uuid.len() == 36
        && uuid.char_indices().all(|(at, c)| match at {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if !shaped {
        return Err(format!("{text:?} isn't <signature uuid>[:<version>]"));
    }
    match version {
        Some("") => Err(format!(
            "{text:?} has an empty version: leave out the colon to match any"
        )),
        version => Ok((uuid.to_ascii_lowercase(), version.map(str::to_owned))),
    }
}

/// An observable filter's pair, normalized as 5.5's lookup normalizes one, with `Any` for any type.
fn observable_pair(kind: &str, value: &str) -> Result<(String, String), ServiceError> {
    if value.is_empty() {
        return Err(invalid("an Observable value can't be empty"));
    }
    if kind == ANY_TYPE {
        return Ok((ANY_TYPE.to_owned(), value.to_owned()));
    }
    let (kind, value) = crate::observables::normalized(kind, value)
        .map_err(|why| invalid(format!("Observable: {why}")))?;
    Ok((kind.as_str().to_owned(), value))
}

/// The three characters that are structural inside a share link's value are percent-encoded, as Python's
/// `quote(safe="")` does: everything but ASCII letters, digits and `-._~`.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Python's `unquote`: each `%XX` is its byte, anything else is itself, and bytes that aren't UTF-8 are
/// U+FFFD.
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && let Some(hex) = bytes.get(at + 1..at + 3)
            && let Ok(hex) = std::str::from_utf8(hex)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A checked filter list as a share link's `f` values, one per entry, ace3's `encode_filter_query`.
pub fn encode(screen: FilterScreen, entries: &[FilterEntry]) -> Result<Vec<String>, ServiceError> {
    check(screen, entries)?
        .iter()
        .map(|entry| {
            let spec = screen.spec(&entry.name).expect("check knows it");
            let values: Vec<String> = entry
                .values
                .iter()
                .map(|value| match value {
                    FilterValue::Text(text) => quote(text),
                    // the type's colon stays literal, so a colon in the value is unambiguous
                    FilterValue::Pair(kind, value) => format!("{}:{}", quote(kind), quote(value)),
                })
                .collect();
            let not = if entry.inverted { "!" } else { "" };
            Ok(format!("{not}{}:{}", spec.slug, values.join(",")))
        })
        .collect()
}

/// A share link's `f` values as a checked filter list, ace3's `decode_filter_query`, with a warning for each
/// filter it names that this screen doesn't have. With `strict`, as the API is, such a filter is refused
/// instead, since a client can't show a warning. A malformed value is refused either way: it's a broken link,
/// and skipping it would show more than its author meant.
pub fn decode(
    screen: FilterScreen,
    params: &[String],
    strict: bool,
) -> Result<(Vec<FilterEntry>, Vec<String>), ServiceError> {
    if params.len() > MAX_FILTER_ENTRIES {
        return Err(invalid(format!(
            "a filter list has at most {MAX_FILTER_ENTRIES} filters"
        )));
    }
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for param in params {
        let raw = param.trim();
        let (inverted, raw) = match raw.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        let Some((slug, values)) = raw.split_once(':') else {
            return Err(invalid(format!(
                "the filter {param:?} isn't <slug>:<value>"
            )));
        };
        if slug.is_empty() {
            return Err(invalid(format!("the filter {param:?} has no name")));
        }
        let Some(spec) = screen.by_slug(&slug.to_ascii_lowercase()) else {
            let why = screen
                .left_out()
                .iter()
                .find(|gone| gone.slug == slug.to_ascii_lowercase())
                .map(|gone| format!("the {} filter isn't here yet: {}", gone.name, gone.why))
                .unwrap_or_else(|| format!("there's no filter {slug:?}"));
            if strict {
                return Err(invalid(why));
            }
            warnings.push(format!("{why}, so the link's {slug} filter was left out"));
            continue;
        };
        let tokens: Vec<&str> = values.split(',').collect();
        if tokens.iter().any(|token| token.is_empty()) {
            return Err(invalid(format!("the filter {slug:?} has an empty value")));
        }
        let values = tokens
            .into_iter()
            .map(|token| match spec.kind {
                FilterKind::Pair => match token.split_once(':') {
                    Some((kind, value)) => Ok(FilterValue::Pair(unquote(kind), unquote(value))),
                    None => Err(invalid(format!(
                        "the {slug} value {token:?} isn't <type>:<value>"
                    ))),
                },
                _ => Ok(FilterValue::Text(unquote(token))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.push(FilterEntry {
            name: spec.name.to_owned(),
            inverted,
            values,
        });
    }
    Ok((check(screen, &entries)?, warnings))
}

/// A checked list's values by filter slug and polarity, for building a query's parameters.
pub(crate) struct Resolved {
    by: BTreeMap<(&'static str, bool), Vec<FilterValue>>,
    now: DateTime<Utc>,
    tz: Tz,
}

/// A date filter's windows, as two arrays of starts and ends.
pub(crate) type Windows = Option<(Vec<DateTime<Utc>>, Vec<DateTime<Utc>>)>;
/// A pair filter's values as two arrays.
pub(crate) type Pairs = Option<(Vec<String>, Vec<String>)>;

impl Resolved {
    /// The list, checked for the screen, with date filters resolved at `now` in `tz`.
    pub(crate) fn new(
        screen: FilterScreen,
        entries: &[FilterEntry],
        now: DateTime<Utc>,
        tz: Tz,
    ) -> Result<Self, ServiceError> {
        let mut by = BTreeMap::new();
        for entry in check(screen, entries)? {
            let spec = screen.spec(&entry.name).expect("check knows it");
            by.insert((spec.slug, entry.inverted), entry.values);
        }
        Ok(Resolved { by, now, tz })
    }

    fn values(&self, slug: &'static str, inverted: bool) -> Option<&Vec<FilterValue>> {
        self.by.get(&(slug, inverted))
    }

    fn texts(&self, slug: &'static str, inverted: bool) -> Option<Vec<String>> {
        self.values(slug, inverted).map(|values| {
            values
                .iter()
                .filter_map(|value| match value {
                    FilterValue::Text(text) => Some(text.clone()),
                    FilterValue::Pair(..) => None,
                })
                .collect()
        })
    }

    /// The values as they are.
    pub(crate) fn names(&self, slug: &'static str, inverted: bool) -> Option<Vec<String>> {
        self.texts(slug, inverted)
    }

    /// The values without the one that means "none", and whether it was there: the disposition by filter's
    /// `None`.
    pub(crate) fn names_or_none(
        &self,
        slug: &'static str,
        inverted: bool,
    ) -> (Option<Vec<String>>, bool) {
        match self.texts(slug, inverted) {
            None => (None, false),
            Some(names) => {
                let none = names.iter().any(|name| name == "None");
                (
                    Some(names.into_iter().filter(|name| name != "None").collect()),
                    none,
                )
            }
        }
    }

    /// ILIKE patterns that contain each value, with `%`, `_` and `\` in it matched as themselves. A
    /// `wildcard` filter's `*` matches anything, as ace3's tag filter does, and the whole value has to match.
    pub(crate) fn patterns(
        &self,
        slug: &'static str,
        inverted: bool,
        wildcard: bool,
    ) -> Option<Vec<String>> {
        self.texts(slug, inverted).map(|values| {
            values
                .iter()
                .map(|value| {
                    let mut pattern = String::with_capacity(value.len() + 2);
                    if !wildcard {
                        pattern.push('%');
                    }
                    for c in value.chars() {
                        match c {
                            '%' | '_' | '\\' => {
                                pattern.push('\\');
                                pattern.push(c);
                            }
                            '*' if wildcard => pattern.push('%'),
                            c => pattern.push(c),
                        }
                    }
                    if !wildcard {
                        pattern.push('%');
                    }
                    pattern
                })
                .collect()
        })
    }

    /// A date filter's windows at this list's moment.
    pub(crate) fn windows(
        &self,
        slug: &'static str,
        inverted: bool,
    ) -> Result<Windows, ServiceError> {
        let Some(values) = self.texts(slug, inverted) else {
            return Ok(None);
        };
        let mut starts = Vec::with_capacity(values.len());
        let mut ends = Vec::with_capacity(values.len());
        for value in values {
            let (start, end) = dates::window(&value, self.now, self.tz).map_err(invalid)?;
            starts.push(start);
            ends.push(end);
        }
        Ok(Some((starts, ends)))
    }

    /// The observable filter's (type, value) pairs, `Any`'s type as the empty string.
    pub(crate) fn observables(&self, inverted: bool) -> Pairs {
        self.values("observable", inverted).map(|values| {
            values
                .iter()
                .filter_map(|value| match value {
                    FilterValue::Pair(kind, value) => Some((
                        if kind == ANY_TYPE {
                            String::new()
                        } else {
                            kind.clone()
                        },
                        value.clone(),
                    )),
                    FilterValue::Text(_) => None,
                })
                .unzip()
        })
    }

    /// A signature filter's (uuid, version) pairs, an empty version matching any.
    pub(crate) fn signatures(&self, slug: &'static str, inverted: bool) -> Pairs {
        self.texts(slug, inverted).map(|values| {
            values
                .iter()
                .filter_map(|value| signature_value(value).ok())
                .map(|(uuid, version)| (uuid, version.unwrap_or_default()))
                .unzip()
        })
    }
}

/// The window a date filter's value names at `now` in `tz`, as (start, end) in UTC: what a list resolves it
/// to, and what an editor can show beside a relative token.
pub fn date_window(
    value: &str,
    now: DateTime<Utc>,
    tz: Tz,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ServiceError> {
    dates::window(value, now, tz).map_err(invalid)
}

/// A pair of arrays as two parameters, each None when the filter isn't set.
pub(crate) fn split<T>(pair: Option<(Vec<T>, Vec<T>)>) -> (Option<Vec<T>>, Option<Vec<T>>) {
    match pair {
        Some((a, b)) => (Some(a), Some(b)),
        None => (None, None),
    }
}

/// A timezone by its IANA name, as a list's date filters are resolved in, or `InvalidRequest`.
pub fn timezone(name: &str) -> Result<Tz, ServiceError> {
    name.parse().map_err(|_| {
        invalid(format!(
            "{name:?} isn't an IANA timezone, such as Europe/London"
        ))
    })
}

impl crate::Service {
    /// The screen with this name once the actor holds its permission, for a descriptor of its filters. An
    /// unknown screen is `NotFound`, whoever asks.
    pub async fn filter_screen(
        &self,
        actor: &crate::Actor,
        name: &str,
    ) -> Result<FilterScreen, ServiceError> {
        let screen = FilterScreen::named(name)
            .ok_or_else(|| ServiceError::NotFound(format!("no filter screen {name:?}")))?;
        self.gate
            .read(actor, "filter_screen", &screen.permission(), &|_tx| {
                Box::pin(async { Ok(()) })
            })
            .await?;
        Ok(screen)
    }

    /// A filter list as a share link's `f` values (`encode`), under the screen's permission.
    pub async fn encode_filters(
        &self,
        actor: &crate::Actor,
        name: &str,
        entries: &[FilterEntry],
    ) -> Result<Vec<String>, ServiceError> {
        let screen = self.filter_screen(actor, name).await?;
        encode(screen, entries)
    }

    /// A share link's `f` values as a filter list, with a warning for each filter left out (`decode`), under
    /// the screen's permission.
    pub async fn decode_filters(
        &self,
        actor: &crate::Actor,
        name: &str,
        params: &[String],
    ) -> Result<(Vec<FilterEntry>, Vec<String>), ServiceError> {
        let screen = self.filter_screen(actor, name).await?;
        decode(screen, params, false)
    }
}
