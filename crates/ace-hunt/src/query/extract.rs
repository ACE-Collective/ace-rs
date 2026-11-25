//! The observables a hunt's mappings take from one row: ace3's `extract_observables_from_event`
//! and what it calls (`saq/query/extraction.py`, `field_lookup.py`, `saq/observables/mapping.py`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map as JsonMap, Value as Json};

use crate::model::{ObservableMapping, RelationshipMapping};
use crate::query::observable::Observable;
use crate::render::{Rendered, Renderer};
use crate::value::{Map as Loaded, py_float_repr, py_repr};

/// A row as the hunt's templates see it, built once per row.
pub struct Row<'a> {
    pub json: &'a JsonMap<String, Json>,
    pub loaded: Loaded,
}

impl<'a> Row<'a> {
    pub fn new(json: &'a JsonMap<String, Json>) -> Row<'a> {
        let loaded = match to_loaded(&Json::Object(json.clone())) {
            crate::value::Value::Map(m) => m,
            _ => Loaded::new(),
        };
        Row { json, loaded }
    }
}

/// A JSON value as Python's `json.loads` gives it.
pub fn to_loaded(value: &Json) -> crate::value::Value {
    use crate::value::Value as V;
    match value {
        Json::Null => V::Null,
        Json::Bool(b) => V::Bool(*b),
        Json::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => V::Int(i128::from(i)),
            (None, Some(u)) => V::Int(i128::from(u)),
            _ => V::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(s) => V::Str(s.clone()),
        Json::Array(items) => V::Seq(items.iter().map(to_loaded).collect()),
        Json::Object(map) => {
            let mut m = Loaded::new();
            for (k, v) in map {
                m.insert(V::Str(k.clone()), to_loaded(v));
            }
            V::Map(m)
        }
    }
}

/// Python's `str()` of a JSON value.
pub fn py_str(value: &Json) -> String {
    match value {
        Json::String(s) => s.clone(),
        other => py_repr_json(other),
    }
}

/// Python's `repr()` of a JSON value.
pub fn py_repr_json(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i.to_string(),
            (None, Some(u)) => u.to_string(),
            _ => py_float_repr(n.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(s) => py_repr(s),
        Json::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(py_repr_json)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Json::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr_json(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `extract_event_value`: the field by its name (`key`), or by a dotted path (`dot`), where a
/// number indexes a list and `*` takes the rest of the path from each item of a list, skipping
/// items it doesn't resolve in. None is a missing field.
pub fn lookup(
    event: &JsonMap<String, Json>,
    lookup_type: Option<&str>,
    field: &str,
) -> Option<Json> {
    if lookup_type != Some("dot") {
        return event.get(field).cloned();
    }
    let mut parts = Vec::new();
    for part in field.split('.') {
        let part = part.trim_matches(char::is_whitespace);
        if part.is_empty() {
            return None;
        }
        parts.push(part);
    }
    path(&Json::Object(event.clone()), &parts)
}

fn path(value: &Json, parts: &[&str]) -> Option<Json> {
    let Some((first, rest)) = parts.split_first() else {
        return Some(value.clone());
    };
    if *first == "*" {
        let Json::Array(items) = value else {
            return None;
        };
        return Some(Json::Array(
            items.iter().filter_map(|item| path(item, rest)).collect(),
        ));
    }
    let next = match (value, first.parse::<i64>()) {
        (Json::Array(items), Ok(i)) => {
            let len = items.len() as i64;
            let i = if i < 0 { i + len } else { i };
            usize::try_from(i).ok().and_then(|i| items.get(i))?
        }
        (Json::Object(map), Err(_)) => map.get(*first)?,
        _ => return None,
    };
    path(next, rest)
}

/// `_is_blank_value`.
pub fn is_blank(value: &Json) -> bool {
    match value {
        Json::Null => true,
        Json::String(s) => s.trim_matches(char::is_whitespace).is_empty(),
        Json::Array(a) => a.is_empty(),
        Json::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Patterns that match a whole value, as `re.fullmatch` does. ace3 logs one that doesn't compile
/// and goes on without it, and so does this: the hunt router's validation reports it.
pub fn whole_value_patterns(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| Regex::new(&format!(r"\A(?:{p})\z")).ok())
        .collect()
}

/// An observable a mapping made, with the field it came from.
pub struct Extracted {
    pub observable: Observable,
    pub matched_field: String,
}

/// A file a mapping made of a value, with `file_name`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FileContent {
    pub file_name: String,
    #[serde(skip)]
    pub content: Vec<u8>,
    pub directives: Vec<String>,
    pub tags: Vec<String>,
    pub volatile: bool,
    pub display_type: Option<String>,
}

/// What the mappings took from a row.
#[derive(Default)]
pub struct Extraction {
    pub observables: Vec<Extracted>,
    pub files: Vec<FileContent>,
    /// The relationships each observable's mapping asks for, as ace3's `relationship_tracking`.
    pub relationships: Vec<(Observable, Vec<RelationshipMapping>)>,
}

/// What extraction needs besides the row.
pub struct Extractor<'a> {
    pub renderer: &'a Renderer,
    pub global_ignored: &'a [Regex],
    /// Whether a type is one ace knows, for a templated type.
    pub valid_type: &'a dyn Fn(&str) -> bool,
}

static FILE: &str = "file";

impl Extractor<'_> {
    /// `extract_observables_from_event`.
    pub fn extract(
        &self,
        row: &Row<'_>,
        mappings: &[ObservableMapping],
        event_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Extraction {
        let mut out = Extraction::default();
        for mapping in mappings {
            let ignored = whole_value_patterns(&mapping.ignored_values);
            let present = |field: &str| {
                lookup(row.json, mapping.field_lookup_type.as_deref(), field)
                    .is_some_and(|v| !is_blank(&v))
            };
            let fields = fields(mapping);
            let groups: Vec<Vec<String>> = if mapping.fields_mode == "any" {
                fields
                    .iter()
                    .filter(|f| present(f))
                    .map(|f| vec![f.clone()])
                    .collect()
            } else if fields.iter().all(|f| present(f)) {
                vec![fields.clone()]
            } else {
                Vec::new()
            };
            for group in groups {
                let field_override = (group.len() == 1).then(|| group[0].clone());
                self.process(
                    mapping,
                    row,
                    event_time,
                    &group[0],
                    field_override,
                    &ignored,
                    &mut out,
                );
            }
        }
        out
    }

    /// `_resolve_mapping_type`.
    fn resolve_type(&self, mapping: &ObservableMapping, row: &Row<'_>) -> Option<String> {
        let rendered = match self.renderer.event(&mapping.kind, &row.loaded, true) {
            Rendered::Text(t) => t,
            _ => return None,
        };
        let resolved = rendered.trim_matches(char::is_whitespace).to_lowercase();
        if resolved != FILE && (self.valid_type)(&resolved) {
            return Some(resolved);
        }
        let fallback = mapping.fallback_type.as_ref()?;
        (self.valid_type)(fallback).then(|| fallback.clone())
    }

    /// `interpret_event_value`: the values as text.
    fn values(
        &self,
        mapping: &ObservableMapping,
        row: &Row<'_>,
        field_override: Option<&str>,
    ) -> Vec<String> {
        let observed: Vec<Json> = match &mapping.value {
            None => {
                let field = field_override.unwrap_or_else(|| fields_first(mapping));
                match lookup(row.json, mapping.field_lookup_type.as_deref(), field) {
                    // a field that resolved as present always resolves again
                    None => return Vec::new(),
                    Some(Json::Array(items)) => items,
                    Some(one) => vec![one],
                }
            }
            Some(template) => self
                .renderer
                .interpolate_strict(template, &row.loaded)
                .into_iter()
                .map(Json::String)
                .collect(),
        };
        let limit = mapping.limit.and_then(|l| usize::try_from(l).ok());
        observed
            .iter()
            .take(limit.unwrap_or(usize::MAX))
            .map(py_str)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn process(
        &self,
        mapping: &ObservableMapping,
        row: &Row<'_>,
        event_time: Option<chrono::DateTime<chrono::Utc>>,
        matched_field: &str,
        field_override: Option<String>,
        ignored: &[Regex],
        out: &mut Extraction,
    ) {
        let kind = if mapping.kind.contains("{{") {
            match self.resolve_type(mapping, row) {
                Some(kind) => kind,
                None => return,
            }
        } else {
            mapping.kind.clone()
        };
        let mut decoded: Option<Vec<u8>> = None;
        for value in self.values(mapping, row, field_override.as_deref()) {
            if value.is_empty()
                || self.global_ignored.iter().any(|p| p.is_match(&value))
                || ignored.iter().any(|p| p.is_match(&value))
            {
                continue;
            }
            if kind == FILE {
                if decoded.is_none()
                    && let Some(decoder) = &mapping.file_decoder
                {
                    decoded = decode(&value, decoder);
                }
                let content = decoded
                    .clone()
                    .unwrap_or_else(|| value.clone().into_bytes());
                let names = mapping
                    .file_name
                    .as_deref()
                    .map(|t| self.renderer.interpolate_strict(t, &row.loaded))
                    .unwrap_or_default();
                for file_name in names.into_iter().filter(|n| !n.is_empty()) {
                    out.files.push(FileContent {
                        file_name,
                        content: content.clone(),
                        directives: self.each(&mapping.directives, row),
                        tags: self.each(&mapping.tags, row),
                        volatile: mapping.volatile,
                        display_type: mapping.display_type.clone(),
                    });
                }
                continue;
            }
            let Some(mut observable) = Observable::create(&kind, &value, mapping.volatile) else {
                continue;
            };
            if mapping.time {
                observable.time = event_time;
            }
            for directive in self.each(&mapping.directives, row) {
                observable.add_directive(&directive);
            }
            for tag in self.each(&mapping.tags, row) {
                observable.add_tag(&tag);
            }
            if mapping.display_type.is_some() {
                observable.display_type = mapping.display_type.clone();
            }
            if mapping.display_value.is_some() {
                observable.display_value = mapping.display_value.clone();
            }
            if !mapping.relationships.is_empty() {
                // a dict keyed by the observable: a later equal one replaces the mappings
                match out
                    .relationships
                    .iter_mut()
                    .find(|(o, _)| o.same(&observable))
                {
                    Some(entry) => entry.1 = mapping.relationships.clone(),
                    None => out
                        .relationships
                        .push((observable.clone(), mapping.relationships.clone())),
                }
            }
            out.observables.push(Extracted {
                observable,
                matched_field: matched_field.to_owned(),
            });
        }
    }

    /// Each template rendered strictly against the row, every non-empty value of each.
    fn each(&self, templates: &[String], row: &Row<'_>) -> Vec<String> {
        templates
            .iter()
            .flat_map(|t| self.renderer.interpolate_strict(t, &row.loaded))
            .filter(|v| !v.is_empty())
            .collect()
    }
}

/// `get_fields`.
pub fn fields(mapping: &ObservableMapping) -> Vec<String> {
    match &mapping.field {
        Some(field) if !field.is_empty() => vec![field.clone()],
        _ => mapping.fields.clone(),
    }
}

fn fields_first(mapping: &ObservableMapping) -> &str {
    match &mapping.field {
        Some(field) if !field.is_empty() && mapping.fields.is_empty() => field,
        _ => mapping
            .fields
            .first()
            .map(String::as_str)
            .unwrap_or_default(),
    }
}

/// `decode_value`: base64 or ASCII hex, None when it doesn't decode.
fn decode(value: &str, decoder: &str) -> Option<Vec<u8>> {
    static NOT_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^0-9a-fA-F]").expect("valid"));
    match decoder {
        "ascii_hex" => {
            let hex = NOT_HEX.replace_all(value, "");
            (0..hex.len() / 2 * 2)
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect()
        }
        "base64" => base64_decode(value),
        _ => None,
    }
}

/// Standard base64, ignoring what isn't in its alphabet.
fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in value.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        bits = bits << 6 | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dotted_paths_index_lists_and_take_each_item_at_a_star() {
        let row = json!({"a": {"b": [{"c": 1}, {"d": 2}, {"c": 3}]}, "x.y": "flat"});
        let row = row.as_object().expect("an object");
        assert_eq!(lookup(row, Some("dot"), "a.b.*.c"), Some(json!([1, 3])));
        assert_eq!(lookup(row, Some("dot"), "a.b.0.c"), Some(json!(1)));
        assert_eq!(lookup(row, Some("dot"), "a.b.-1.c"), Some(json!(3)));
        assert_eq!(lookup(row, Some("dot"), "a..b"), None);
        assert_eq!(lookup(row, Some("key"), "x.y"), Some(json!("flat")));
        assert_eq!(lookup(row, None, "a.b"), None);
    }

    #[test]
    fn values_print_as_python_s_str() {
        assert_eq!(py_str(&json!("x")), "x");
        assert_eq!(py_str(&json!(true)), "True");
        assert_eq!(py_str(&json!(null)), "None");
        assert_eq!(py_str(&json!(1.5)), "1.5");
        assert_eq!(py_str(&json!({"a": [1, "b"]})), "{'a': [1, 'b']}");
    }
}
