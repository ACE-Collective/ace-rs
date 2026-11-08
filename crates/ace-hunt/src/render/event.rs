//! An event made ready for a template as ace3's `saq/query/template_rendering.py` makes it: flat
//! dotted keys nested (`_expand_dotted_keys`), and the paths a template reads resolved, set and
//! iterated (`_resolve_path`, `_set_path`, the axes of `render_event_templates_multi`).

use super::rewrite::Segment;
use crate::value::{Map, Value};

/// `_expand_dotted_keys`: `{"device.hostname": "x"}` is `{"device": {"hostname": "x"}}`, a `{}`
/// ending a segment is dropped (Splunk's multivalue marker), and where a flat key and a nested
/// one collide the nested form wins.
pub fn expand_dotted_keys(event: &Map) -> Map {
    let mut result = Map::new();
    for (raw_key, value) in event.iter() {
        let Value::Str(raw) = raw_key else {
            result.insert(raw_key.clone(), value.clone());
            continue;
        };
        // the split drops empty segments before `{}` is removed, so `a.{}` keeps an empty one
        let parts: Vec<String> = raw
            .split('.')
            .filter(|p| !p.is_empty())
            .map(|p| p.strip_suffix("{}").unwrap_or(p).to_owned())
            .collect();
        if parts.is_empty() {
            continue;
        }
        insert(&mut result, &parts, value);
    }
    result
}

fn insert(cursor: &mut Map, parts: &[String], value: &Value) {
    let key = Value::Str(parts[0].clone());
    if parts.len() == 1 {
        if matches!(cursor.get_value(&key), Some(Value::Map(_))) && !matches!(value, Value::Map(_))
        {
            // the nested form is already there; keep it
            return;
        }
        cursor.insert(key, value.clone());
        return;
    }
    match cursor.get_value(&key) {
        Some(Value::Map(_)) => {}
        _ => cursor.insert(key.clone(), Value::Map(Map::new())),
    }
    if let Some(Value::Map(next)) = cursor.get_mut(&parts[0]) {
        insert(next, &parts[1..], value);
    }
}

fn segment_value(s: &Segment) -> Value {
    match s {
        Segment::Name(n) => Value::Str(n.clone()),
        Segment::Index(i) => Value::Int(*i),
    }
}

/// `_resolve_path`: the value at `path`, a dict key or a list index from 0, if there is one.
pub fn resolve<'a>(data: &'a Map, path: &[Segment]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let mut cursor = data.get_value(&segment_value(first))?;
    for segment in rest {
        cursor = match (cursor, segment) {
            (Value::Map(m), s) => m.get_value(&segment_value(s))?,
            (Value::Seq(items), Segment::Index(i)) => {
                let i = usize::try_from(*i).ok()?;
                items.get(i)?
            }
            _ => return None,
        };
    }
    Some(cursor)
}

/// `_set_path`: sets `path` to `value`, replacing anything on the way that isn't a dict with one.
pub fn set(data: &mut Map, path: &[Segment], value: Value) {
    let Some((last, init)) = path.split_last() else {
        return;
    };
    let mut cursor = data;
    for segment in init {
        let key = segment_value(segment);
        if !matches!(cursor.get_value(&key), Some(Value::Map(_))) {
            cursor.insert(key.clone(), Value::Map(Map::new()));
        }
        cursor = match cursor.get_value_mut(&key) {
            Some(Value::Map(m)) => m,
            _ => return,
        };
    }
    cursor.insert(segment_value(last), value);
}
