//! The search query language: ace3's `saq/search/syntax.py`.
//!
//! A query is a mix of field terms and free text. A literal is only looked up when a field term names
//! it; everything else is free text for the semantic lanes.
//!
//! ```text
//! tag:phish                        the tag
//! ipv4:10.20.30.40                 an observable, by its type
//! observable:url:https://evil.com  the explicit form, for a value with colons in it
//! uuid:1f2e3d4c-…                  an alert's id, or its first eight characters or more
//! queue:default                    a narrowing filter
//! disposition:DELIVERY,IGNORE      one term, values ORed
//! alert_date:-7d                   a relative window
//! -tag:whitelisted                 inverted (! works too)
//! tag:"vendor mailer"              quoted, for a value with a space or a comma
//! docusign invoice                 free text
//! ```
//!
//! The field names are the alert screen's filter slugs (`crate::filters`), ace3's and permanent, and
//! every observable type's name. A prefix that is neither isn't a term, and its token stays free text as
//! it was typed, which keeps `https://evil.com` and `C:\windows\system32` out of the parser. A slug ace3
//! has and this screen doesn't yet (`FilterScreen::left_out`) is a term that can't be honored, and says
//! so.
//!
//! As in ace3, values are literal where a share link percent-encodes them, and `uuid:` is the alert's
//! id, so the observable type of that name is written `observable:uuid:<value>`.
//!
//! What differs: a value is checked by `filters::check`, the one gate for a filter, so what a term
//! refuses is what the alert list refuses. ace3 normalizes an observable's value through its
//! observable class; ace4's types take any value but a file's, which is its sha256.

use std::sync::LazyLock;

use ace_results::ObservableKind;
use regex::Regex;

use crate::filters::{self, FilterEntry, FilterScreen, FilterValue};

/// The most field terms a query has: ace3's `MAX_TERMS`.
pub const MAX_TERMS: usize = 32;
/// The most values one term has: ace3's `MAX_VALUES_PER_TERM`.
pub const MAX_VALUES_PER_TERM: usize = 64;

static TERM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)^(?P<invert>[-!])?(?P<name>[A-Za-z0-9_]+):(?P<value>.+)$").expect("a pattern")
});
static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
        .expect("a pattern")
});
static UUID_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-f0-9]{8}(-[a-f0-9]{0,4}){0,4}$").expect("a pattern"));
/// What looks like an identifier pasted bare: only for the hint, never to match anything.
static IDENTIFIER_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)^(?:(?:\d{1,3}\.){3}\d{1,3}",
        r"|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}",
        r"|[^@\s]+@[^@\s]+\.[a-z]{2,}",
        r"|[a-z][a-z0-9+.-]*://\S+)$",
    ))
    .expect("a pattern")
});
static PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("\u{0}(\\d+)\u{0}").expect("a pattern"));

/// A term the exact lane looks up: one that isn't inverted and has no wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactTerm {
    /// (type, value) pairs.
    Observables(Vec<(String, String)>),
    Tags(Vec<String>),
    /// Alert ids, or the first characters of one, lowercased.
    Uuids(Vec<String>),
}

/// What a query means, split by where each part is applied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedQuery {
    /// The free text, for the semantic lanes. Empty means they don't run: an embedding of nothing still
    /// has a nearest neighbour.
    pub text: String,
    /// The exact lane's lookups.
    pub exact: Vec<ExactTerm>,
    /// Everything else, as filter entries.
    pub filters: Vec<FilterEntry>,
    /// What couldn't be honored. A term is reported, never dropped: a dropped filter widens the result.
    pub errors: Vec<String>,
}

impl ParsedQuery {
    pub fn is_empty(&self) -> bool {
        self.text.is_empty() && self.exact.is_empty() && self.filters.is_empty()
    }

    /// A "did you mean" line when the query is a bare indicator with no field term: ace3's `hint`.
    pub fn hint(&self) -> Option<String> {
        if !self.exact.is_empty() || self.text.is_empty() {
            return None;
        }
        self.text
            .split_whitespace()
            .find(|token| IDENTIFIER_HINT.is_match(token))
            .map(|token| {
                format!(
                    "No exact match was searched for. To find every alert containing {token:?}, use an \
                     observable type, e.g. ipv4:{token} or observable:<type>:{token}."
                )
            })
    }
}

/// Each `"..."` span as a placeholder with no space, colon or comma in it, so it survives the splits:
/// ace3's `mask_quoted`.
fn mask_quoted(query: &str) -> Result<(String, Vec<String>), String> {
    let mut masked = String::with_capacity(query.len());
    let mut values = Vec::new();
    let mut rest = query;
    while let Some(start) = rest.find('"') {
        let Some(length) = rest[start + 1..].find('"') else {
            return Err("unterminated quote in query".to_owned());
        };
        masked.push_str(&rest[..start]);
        masked.push_str(&format!("\u{0}{}\u{0}", values.len()));
        values.push(rest[start + 1..start + 1 + length].to_owned());
        rest = &rest[start + 1 + length + 1..];
    }
    masked.push_str(rest);
    Ok((masked, values))
}

fn unmask(text: &str, quoted: &[String]) -> String {
    PLACEHOLDER
        .replace_all(text, |found: &regex::Captures<'_>| {
            found[1]
                .parse::<usize>()
                .ok()
                .and_then(|index| quoted.get(index))
                .cloned()
                .unwrap_or_default()
        })
        .into_owned()
}

fn split_values(raw: &str, quoted: &[String]) -> Vec<String> {
    raw.split(',').map(|value| unmask(value, quoted)).collect()
}

/// What a prefix names.
enum Field {
    AlertUuid,
    /// One of the alert screen's filters.
    Filter(&'static filters::FilterSpec),
    /// One of ace3's this screen doesn't have yet.
    LeftOut(&'static filters::LeftOut),
    Observable(ObservableKind),
}

/// The field a prefix names, or None when it names none: `uuid` first, then a filter's slug, then an
/// observable type, as ace3's `resolve_field`.
fn resolve_field(name: &str) -> Option<Field> {
    let lowered = name.to_lowercase();
    if lowered == "uuid" {
        return Some(Field::AlertUuid);
    }
    let screen = FilterScreen::Alerts;
    if let Some(spec) = screen.filters().iter().find(|spec| spec.slug == lowered) {
        return Some(Field::Filter(spec));
    }
    if let Some(gone) = screen.left_out().iter().find(|gone| gone.slug == lowered) {
        return Some(Field::LeftOut(gone));
    }
    ObservableKind::all()
        .iter()
        .find(|kind| kind.as_str().to_lowercase() == lowered)
        .map(|kind| Field::Observable(*kind))
}

/// One checked entry, or the reason `filters::check` refuses it.
fn checked(entry: FilterEntry) -> Result<FilterEntry, String> {
    filters::check(FilterScreen::Alerts, &[entry])
        .map_err(|error| error.to_string())
        .and_then(|mut entries| entries.pop().ok_or_else(|| "no values".to_owned()))
}

/// A term's values checked one at a time, so one bad value is reported and the rest kept.
fn checked_values(
    name: &str,
    label: &str,
    inverted: bool,
    values: Vec<FilterValue>,
    show: impl Fn(&FilterValue) -> String,
    errors: &mut Vec<String>,
) -> Vec<FilterValue> {
    let mut kept = Vec::new();
    for value in values {
        match checked(FilterEntry::new(name, inverted, vec![value.clone()])) {
            Ok(mut entry) => kept.append(&mut entry.values),
            Err(why) => errors.push(format!("{label}:{} can't be used: {why}", show(&value))),
        }
    }
    kept
}

fn add_filter(filters: &mut Vec<FilterEntry>, entry: FilterEntry) {
    // repeating a field means "either", so `queue:a queue:b` is one entry: ace3's `_add_filter_entry`
    if let Some(existing) = filters
        .iter_mut()
        .find(|existing| existing.name == entry.name && existing.inverted == entry.inverted)
    {
        for value in entry.values {
            if !existing.values.contains(&value) {
                existing.values.push(value);
            }
        }
    } else {
        filters.push(entry);
    }
}

/// Splits a query into its field terms and its free text: ace3's `parse_search_query`.
pub fn parse(query: &str) -> ParsedQuery {
    let query = query.trim();
    if query.is_empty() {
        return ParsedQuery::default();
    }
    let (masked, quoted) = match mask_quoted(query) {
        Ok(masked) => masked,
        Err(error) => {
            return ParsedQuery {
                errors: vec![error],
                ..ParsedQuery::default()
            };
        }
    };
    let mut parsed = ParsedQuery::default();
    let mut free = Vec::new();
    let mut terms = 0;
    for token in masked.split_whitespace() {
        let Some((field, inverted, raw)) = TERM.captures(token).and_then(|found| {
            resolve_field(&found["name"]).map(|field| {
                (
                    field,
                    found.name("invert").is_some(),
                    found["value"].to_owned(),
                )
            })
        }) else {
            free.push(unmask(token, &quoted));
            continue;
        };
        let mut values = split_values(&raw, &quoted);
        let label = match &field {
            Field::AlertUuid => "uuid".to_owned(),
            Field::Filter(spec) => spec.slug.to_owned(),
            Field::LeftOut(gone) => gone.slug.to_owned(),
            Field::Observable(kind) => kind.as_str().to_owned(),
        };
        if values.len() > MAX_VALUES_PER_TERM {
            parsed.errors.push(format!(
                "{label}: has more than {MAX_VALUES_PER_TERM} values"
            ));
            values.truncate(MAX_VALUES_PER_TERM);
        }
        let errors = &mut parsed.errors;
        let text = |value: &FilterValue| match value {
            FilterValue::Text(text) => format!("{text:?}"),
            FilterValue::Pair(kind, value) => format!("{kind}:{value:?}"),
        };
        let mut added = false;
        match field {
            Field::AlertUuid => {
                if inverted {
                    errors.push(
                        "uuid: cannot be inverted (there is no 'not this alert' filter)".to_owned(),
                    );
                    continue;
                }
                let mut resolved = Vec::new();
                for value in values {
                    let lowered = value.trim().to_lowercase();
                    if UUID.is_match(&lowered) || UUID_PREFIX.is_match(&lowered) {
                        resolved.push(lowered);
                    } else {
                        errors.push(format!(
                            "uuid:{value:?} is not an alert uuid or a uuid prefix"
                        ));
                    }
                }
                if !resolved.is_empty() {
                    parsed.exact.push(ExactTerm::Uuids(resolved));
                    added = true;
                }
            }
            Field::LeftOut(gone) => {
                errors.push(format!(
                    "{}: isn't a filter here yet: {}",
                    gone.slug, gone.why
                ));
            }
            Field::Observable(_) | Field::Filter(_) => {
                let pairs = match &field {
                    Field::Observable(kind) => Some(
                        values
                            .iter()
                            .map(|value| FilterValue::Pair(kind.as_str().to_owned(), value.clone()))
                            .collect::<Vec<_>>(),
                    ),
                    Field::Filter(spec) if spec.slug == "observable" => {
                        // the explicit form carries the type: split at the first colon only
                        let mut pairs = Vec::new();
                        for value in &values {
                            match value.split_once(':') {
                                Some((kind, value)) if !value.is_empty() => {
                                    pairs
                                        .push(FilterValue::Pair(kind.to_owned(), value.to_owned()));
                                }
                                _ => errors.push(format!(
                                    "observable:{value:?} must be written observable:<type>:<value>"
                                )),
                            }
                        }
                        Some(pairs)
                    }
                    _ => None,
                };
                let (name, values) = match (&field, pairs) {
                    (_, Some(pairs)) => ("Observable", pairs),
                    (Field::Filter(spec), None) => (
                        spec.name,
                        values.into_iter().map(FilterValue::Text).collect(),
                    ),
                    _ => continue,
                };
                let values = checked_values(name, &label, inverted, values, text, errors);
                if values.is_empty() {
                    continue;
                }
                added = true;
                // "alerts without this" narrows and there is nothing to report a hit for, and a
                // wildcard tag isn't a name to look up: both are filters, as in ace3
                let wildcard = name == "Tag"
                    && values.iter().any(
                        |value| matches!(value, FilterValue::Text(text) if text.contains('*')),
                    );
                if name == "Observable" && !inverted {
                    parsed.exact.push(ExactTerm::Observables(
                        values
                            .into_iter()
                            .filter_map(|value| match value {
                                FilterValue::Pair(kind, value) => Some((kind, value)),
                                FilterValue::Text(_) => None,
                            })
                            .collect(),
                    ));
                } else if name == "Tag" && !inverted && !wildcard {
                    parsed.exact.push(ExactTerm::Tags(
                        values
                            .into_iter()
                            .filter_map(|value| match value {
                                FilterValue::Text(text) => Some(text),
                                FilterValue::Pair(..) => None,
                            })
                            .collect(),
                    ));
                } else {
                    add_filter(
                        &mut parsed.filters,
                        FilterEntry::new(name, inverted, values),
                    );
                }
            }
        }
        if added {
            terms += 1;
        }
        if terms > MAX_TERMS {
            parsed.errors.push(format!(
                "too many field terms (at most {MAX_TERMS}); the rest were ignored"
            ));
            break;
        }
    }
    parsed.text = free.join(" ").trim().to_owned();
    parsed
}
