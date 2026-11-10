//! Python 3.14's `pprint.pformat` and `repr` of what `json.loads` returns (`ace_pycompat::json`), for
//! the exif module, which writes exiftool's metadata as `pprint.pformat(metadata)` (ace3's
//! `exif.py`). A port of `pprint.PrettyPrinter` with its defaults (indent 1, width 80, sorted dicts,
//! no depth limit, not compact), for the types JSON gives: dicts, lists, strings, ints, floats, bools
//! and None.

use ace_pycompat::json::{JsonStr, Value, float_repr};
use ace_pycompat::pystr::{is_space, splitlines_keepends};
use ace_pycompat::repr::repr_cps;

/// pprint's default width.
const WIDTH: usize = 80;

/// The nesting at which ace3's `pformat` raises `RecursionError`: 330 lists in a dict at the top of a
/// Python 3.14 process, measured in ace3's container (`docs/measurements/sandbox-modules.md`). In
/// ace3's worker the engine's frames come first, so its limit is somewhat lower.
pub const MAX_PFORMAT_DEPTH: usize = 330;

/// `pprint.pformat(value)`, or None where Python raises `RecursionError`.
pub fn pformat(value: &Value) -> Option<String> {
    // the dict, its lists and the scalar in the last
    if depth(value) > MAX_PFORMAT_DEPTH + 2 {
        return None;
    }
    let mut out = String::new();
    format(value, &mut out, 0, 0, 0);
    Some(out)
}

/// How deeply `value` nests: 1 for a scalar.
fn depth(value: &Value) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(value, 1)];
    while let Some((value, level)) = stack.pop() {
        deepest = deepest.max(level);
        match value {
            Value::Array(items) => stack.extend(items.iter().map(|v| (v, level + 1))),
            Value::Object(members) => stack.extend(members.iter().map(|(_, v)| (v, level + 1))),
            _ => {}
        }
    }
    deepest
}

/// `len()` of a Python string.
fn py_len(text: &str) -> usize {
    text.chars().count()
}

fn str_repr(s: &JsonStr) -> String {
    repr_cps(&s.code_points())
}

fn text_repr(text: &str) -> String {
    repr_cps(&text.chars().map(|c| c as u32).collect::<Vec<_>>())
}

/// A dict's items as `sorted(object.items(), key=_safe_tuple)` gives them: by key, as Python
/// compares strings, by code point.
fn sorted_items(members: &[(JsonStr, Value)]) -> Vec<&(JsonStr, Value)> {
    let mut items: Vec<&(JsonStr, Value)> = members.iter().collect();
    items.sort_by_key(|(key, _)| key.code_points());
    items
}

/// `PrettyPrinter._safe_repr`: dicts sorted.
pub fn safe_repr(value: &Value) -> String {
    match value {
        Value::Object(members) if members.is_empty() => "{}".to_owned(),
        Value::Object(members) => {
            let parts: Vec<String> = sorted_items(members)
                .into_iter()
                .map(|(key, value)| format!("{}: {}", str_repr(key), safe_repr(value)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        Value::Array(items) if items.is_empty() => "[]".to_owned(),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(safe_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        scalar => scalar_repr(scalar),
    }
}

/// `repr()` of a value, dicts in their own order, as the builtin gives it.
pub fn repr(value: &Value) -> String {
    match value {
        Value::Object(members) => {
            let parts: Vec<String> = members
                .iter()
                .map(|(key, value)| format!("{}: {}", str_repr(key), repr(value)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(repr).collect();
            format!("[{}]", parts.join(", "))
        }
        scalar => scalar_repr(scalar),
    }
}

/// `str()` of a value, as an f-string writes it.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Str(s) => s.as_str().to_owned(),
        other => repr(other),
    }
}

fn scalar_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Int(digits) => digits.clone(),
        Value::Float(f) => float_repr(*f),
        Value::Str(s) => str_repr(s),
        Value::Array(_) | Value::Object(_) => unreachable!("not a scalar"),
    }
}

/// `PrettyPrinter._format`.
fn format(value: &Value, out: &mut String, indent: usize, allowance: usize, level: usize) {
    let rep = safe_repr(value);
    let max_width = WIDTH.saturating_sub(indent).saturating_sub(allowance);
    // `self._width - indent - allowance` may be negative in Python, and every repr is longer then
    let too_wide = WIDTH < indent + allowance || py_len(&rep) > max_width;
    if too_wide {
        match value {
            Value::Object(members) => {
                out.push('{');
                if !members.is_empty() {
                    format_dict_items(
                        &sorted_items(members),
                        out,
                        indent,
                        allowance + 1,
                        level + 1,
                    );
                }
                out.push('}');
                return;
            }
            Value::Array(items) => {
                out.push('[');
                format_items(items, out, indent, allowance + 1, level + 1);
                out.push(']');
                return;
            }
            Value::Str(s) => {
                pprint_str(s.as_str(), out, indent, allowance, level + 1);
                return;
            }
            _ => {}
        }
    }
    out.push_str(&rep);
}

/// `PrettyPrinter._format_dict_items`.
fn format_dict_items(
    items: &[&(JsonStr, Value)],
    out: &mut String,
    indent: usize,
    allowance: usize,
    level: usize,
) {
    let indent = indent + 1;
    let delimiter = format!(",\n{}", " ".repeat(indent));
    let last_index = items.len() - 1;
    for (i, (key, value)) in items.iter().enumerate() {
        let last = i == last_index;
        let rep = str_repr(key);
        out.push_str(&rep);
        out.push_str(": ");
        format(
            value,
            out,
            indent + py_len(&rep) + 2,
            if last { allowance } else { 1 },
            level,
        );
        if !last {
            out.push_str(&delimiter);
        }
    }
}

/// `PrettyPrinter._format_items`, not compact.
fn format_items(items: &[Value], out: &mut String, indent: usize, allowance: usize, level: usize) {
    let indent = indent + 1;
    let delimiter = format!(",\n{}", " ".repeat(indent));
    let last_index = items.len().saturating_sub(1);
    for (i, value) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(&delimiter);
        }
        let last = i == last_index;
        format(value, out, indent, if last { allowance } else { 1 }, level);
    }
}

/// `re.findall(r'\S*\s*', line)` without its empty last match.
fn parts_of(line: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && !is_space(chars[i].1) {
            i += 1;
        }
        while i < chars.len() && is_space(chars[i].1) {
            i += 1;
        }
        let end = chars.get(i).map_or(line.len(), |&(at, _)| at);
        parts.push(&line[start..end]);
        start = end;
    }
    parts
}

/// `PrettyPrinter._pprint_str`.
fn pprint_str(text: &str, out: &mut String, indent: usize, allowance: usize, level: usize) {
    if text.is_empty() {
        out.push_str(&text_repr(text));
        return;
    }
    let mut chunks: Vec<String> = Vec::new();
    let lines = splitlines_keepends(text);
    let (indent, allowance) = if level == 1 {
        (indent + 1, allowance + 1)
    } else {
        (indent, allowance)
    };
    let max_width = WIDTH as isize - indent as isize;
    let mut max_width1 = max_width;
    let mut rep = String::new();
    for (i, line) in lines.iter().enumerate() {
        rep = text_repr(line);
        if i == lines.len() - 1 {
            max_width1 -= allowance as isize;
        }
        if py_len(&rep) as isize <= max_width1 {
            chunks.push(rep.clone());
        } else {
            let parts = parts_of(line);
            let mut max_width2 = max_width;
            let mut current = String::new();
            for (j, part) in parts.iter().enumerate() {
                let candidate = format!("{current}{part}");
                if j == parts.len() - 1 && i == lines.len() - 1 {
                    max_width2 -= allowance as isize;
                }
                if py_len(&text_repr(&candidate)) as isize > max_width2 {
                    if !current.is_empty() {
                        chunks.push(text_repr(&current));
                    }
                    current = (*part).to_owned();
                } else {
                    current = candidate;
                }
            }
            if !current.is_empty() {
                chunks.push(text_repr(&current));
            }
        }
    }
    if chunks.len() == 1 {
        out.push_str(&rep);
        return;
    }
    if level == 1 {
        out.push('(');
    }
    for (i, chunk) in chunks.iter().enumerate() {
        if i > 0 {
            out.push('\n');
            out.push_str(&" ".repeat(indent));
        }
        out.push_str(chunk);
    }
    if level == 1 {
        out.push(')');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_pycompat::json::loads;

    fn pf(json: &str) -> String {
        pformat(&loads(json).unwrap()).unwrap()
    }

    /// Each against `pprint.pformat(json.loads(...))` in ace3's container.
    #[test]
    fn it_formats_as_python() {
        assert_eq!(
            pf(r#"{"b": 1, "a": [1, 2.5, true, null]}"#),
            "{'a': [1, 2.5, True, None], 'b': 1}"
        );
        assert_eq!(
            pf(
                r#"{"SourceFile": "x", "PDF:Producer": "Skia/PDF m121 with a much longer producer string that wraps", "PDF:PageCount": 2}"#
            ),
            "{'PDF:PageCount': 2,\n 'PDF:Producer': 'Skia/PDF m121 with a much longer producer string that wraps',\n 'SourceFile': 'x'}"
        );
        assert_eq!(
            pf(
                r#"{"XMP:Description": "line one\nline two that is rather long and goes past the width of eighty columns for sure\nthree", "a": {"nested": {"deeper": ["x", "y"], "more": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}}}"#
            ),
            "{'XMP:Description': 'line one\\n'\n                    'line two that is rather long and goes past the width of '\n                    'eighty columns for sure\\n'\n                    'three',\n 'a': {'nested': {'deeper': ['x', 'y'],\n                  'more': 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'}}}"
        );
        assert_eq!(
            pf(
                r#"{"k": ["aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccc", "dddddddddddddddddddd"]}"#
            ),
            "{'k': ['aaaaaaaaaaaaaaaaaaaa',\n       'bbbbbbbbbbbbbbbbbbbb',\n       'cccccccccccccccccccc',\n       'dddddddddddddddddddd']}"
        );
    }

    #[test]
    fn str_and_repr_are_pythons() {
        let value = loads(r#"[1, "a'b", {"z": 1, "a": 2}, 1.0, 1e20]"#).unwrap();
        assert_eq!(repr(&value), r#"[1, "a'b", {'z': 1, 'a': 2}, 1.0, 1e+20]"#);
        assert_eq!(py_str(&loads(r#""text""#).unwrap()), "text");
    }

    #[test]
    fn too_deep_is_a_recursion_error() {
        let deep = format!("{{\"k\": {}1{}}}", "[".repeat(331), "]".repeat(331));
        assert!(pformat(&loads(&deep).unwrap()).is_none());
        let fine = format!("{{\"k\": {}1{}}}", "[".repeat(330), "]".repeat(330));
        assert!(pformat(&loads(&fine).unwrap()).is_some());
    }
}
