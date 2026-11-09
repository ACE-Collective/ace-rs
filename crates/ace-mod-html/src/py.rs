//! The bits of Python the four modules lean on: `os.path.splitext`, `str()` of a JSON value,
//! `json.dumps`' length with `ensure_ascii`, and ace3's `map_mimetype_to_file_ext`.

use std::collections::HashMap;
use std::sync::LazyLock;

use ace_pycompat::json::{JsonStr, Value, float_repr};
use ace_pycompat::repr::repr_cps;

/// ace3's `NAME_MAX_BYTES`: a longer name fails to open, as on ace3's file system.
pub const NAME_MAX_BYTES: usize = 255;

/// `os.path.splitext(name)[0]`, for a name with no `/`: the name without its last extension,
/// leading dots not counting as one.
pub fn splitext_root(name: &str) -> &str {
    let Some(dot) = name.rfind('.') else {
        return name;
    };
    if name[..dot].bytes().all(|b| b == b'.') {
        return name;
    }
    &name[..dot]
}

/// `name.lower().endswith(suffix)`, for an ASCII `suffix`.
pub fn ends_with_lower(name: &str, suffix: &str) -> bool {
    ace_pycompat::pystr::lower(name).ends_with(suffix)
}

/// ace3's mime type table, `etc/mime.types`, as type and first extension.
static MIME_TYPES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut table = HashMap::new();
    for line in include_str!("mime_types.tsv").lines() {
        if let Some((mime, ext)) = line.split_once('\t') {
            table.entry(mime).or_insert(ext);
        }
    }
    table
});

/// `map_mimetype_to_file_ext(mime_type)`: the first extension `etc/mime.types` gives the type,
/// matched exactly, or `bin`.
pub fn mime_extension(mime_type: &str) -> &'static str {
    MIME_TYPES.get(mime_type).copied().unwrap_or("bin")
}

/// `repr()` of a str that came out of JSON, lone surrogates included.
fn repr_json_str(s: &JsonStr) -> String {
    repr_cps(&s.code_points())
}

/// `repr()` of a JSON value, for the members of a list or a dict.
fn repr_value(value: &Value, out: &mut String) {
    match value {
        Value::Str(s) => out.push_str(&repr_json_str(s)),
        other => str_value(other, out),
    }
}

fn str_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("None"),
        Value::Bool(true) => out.push_str("True"),
        Value::Bool(false) => out.push_str("False"),
        Value::Int(digits) => out.push_str(digits),
        Value::Float(f) => out.push_str(&float_repr(*f)),
        Value::Str(s) => out.push_str(&String::from_utf16_lossy(&surrogates_as_question_marks(s))),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                repr_value(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            out.push('{');
            for (i, (key, item)) in members.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&repr_json_str(key));
                out.push_str(": ");
                repr_value(item, out);
            }
            out.push('}');
        }
    }
}

/// `str(value)` for a value `json.loads` returned. A str's lone surrogates can't be text here;
/// each is a `?`, as the string encodes with `errors="replace"`.
pub fn py_str(value: &Value) -> String {
    let mut out = String::new();
    str_value(value, &mut out);
    out
}

/// A str's UTF-16, its lone surrogates as `?`.
fn surrogates_as_question_marks(s: &JsonStr) -> Vec<u16> {
    let mut units = Vec::new();
    for cp in s.code_points() {
        match char::from_u32(cp) {
            Some(c) => {
                let mut buf = [0u16; 2];
                units.extend_from_slice(c.encode_utf16(&mut buf));
            }
            None => units.push(u16::from(b'?')),
        }
    }
    units
}

/// `s.encode("utf-8", errors="replace")` for a str from JSON.
pub fn encode_replace(s: &JsonStr) -> Vec<u8> {
    if !s.has_surrogates() {
        return s.as_str().as_bytes().to_vec();
    }
    String::from_utf16_lossy(&surrogates_as_question_marks(s)).into_bytes()
}

/// The length of `json.dumps(s)` for a str, with `ensure_ascii`: quotes, `\"`, `\\` and the
/// short escapes are two characters, other controls and anything past `~` six, or twelve past
/// the Basic Multilingual Plane.
pub fn json_str_len(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            ' '..='~' => 1,
            c if (c as u32) < 0x10000 => 6,
            _ => 12,
        })
        .sum::<usize>()
}

/// `s[:n]` in characters.
pub fn truncate_chars(s: &str, n: usize) -> Option<&str> {
    s.char_indices().nth(n).map(|(at, _)| &s[..at])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitext_keeps_leading_dots() {
        assert_eq!(splitext_root("page.html"), "page");
        assert_eq!(splitext_root("a.b.c"), "a.b");
        assert_eq!(splitext_root(".bashrc"), ".bashrc");
        assert_eq!(splitext_root("..x.y"), "..x");
        assert_eq!(splitext_root("noext"), "noext");
        assert_eq!(splitext_root("x."), "x");
    }

    #[test]
    fn mime_types_are_ace3_s() {
        assert_eq!(mime_extension("image/png"), "png");
        assert_eq!(mime_extension("text/html"), "html");
        assert_eq!(mime_extension("text/javascript"), "js");
        assert_eq!(mime_extension("application/javascript"), "bin");
        assert_eq!(mime_extension("image/jpeg"), "jpeg");
        assert_eq!(mime_extension("IMAGE/PNG"), "bin");
        assert_eq!(mime_extension("x/y"), "bin");
    }

    #[test]
    fn str_of_json_values_is_python_s() {
        let value =
            ace_pycompat::json::loads(r#"[1, 2.5, null, true, "a'b", {"k": [false]}, 1e400]"#)
                .expect("parses");
        assert_eq!(
            py_str(&value),
            r#"[1, 2.5, None, True, "a'b", {'k': [False]}, inf]"#
        );
        assert_eq!(
            py_str(&ace_pycompat::json::loads(r#""x""#).expect("parses")),
            "x"
        );
    }

    #[test]
    fn json_lengths_are_ensure_ascii_s() {
        assert_eq!(json_str_len("ab"), 4);
        assert_eq!(json_str_len("a\"\n"), 7);
        assert_eq!(json_str_len("\u{1}\u{7f}\u{e9}"), 20);
        assert_eq!(json_str_len("\u{1f600}"), 14);
    }
}
