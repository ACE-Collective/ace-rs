//! What `IcalUrlFinder` uses of icalendar 7.3.0: `Contentlines.from_ical`, `Contentline.parts()`
//! (only whether it raises ValueError, its `FMTTYPE` parameter and its value) and
//! `unescape_char`.

use ace_pycompat::pystr;

/// `Contentlines.from_ical(st)`: the text unfolded, split on `\r?\n`, empty lines left out.
pub fn content_lines(st: &str) -> Vec<String> {
    let unfolded = unfold(st);
    let mut lines = Vec::new();
    let mut rest = unfolded.as_str();
    loop {
        let (line, next) = match rest.find('\n') {
            Some(at) => {
                let line = &rest[..at];
                (
                    line.strip_suffix('\r').unwrap_or(line),
                    Some(&rest[at + 1..]),
                )
            }
            None => (rest, None),
        };
        if !line.is_empty() {
            lines.push(line.to_owned());
        }
        match next {
            Some(next) => rest = next,
            None => break,
        }
    }
    lines
}

/// `UFOLD.sub("", st)`, which removes what `(\r?\n)+[ \t]` matches.
fn unfold(st: &str) -> String {
    let bytes = st.as_bytes();
    let mut out = String::with_capacity(st.len());
    let mut copied = 0;
    let mut i = 0;
    let run_at = |j: usize| {
        if bytes[j..].starts_with(b"\r\n") {
            Some(2)
        } else if bytes[j] == b'\n' {
            Some(1)
        } else {
            None
        }
    };
    while i < bytes.len() {
        let Some(first) = run_at(i) else {
            i += 1;
            continue;
        };
        let mut j = i + first;
        while j < bytes.len()
            && let Some(more) = run_at(j)
        {
            j += more;
        }
        if matches!(bytes.get(j), Some(b' ' | b'\t')) {
            out.push_str(&st[copied..i]);
            copied = j + 1;
            i = j + 1;
        } else {
            i = j;
        }
    }
    out.push_str(&st[copied..]);
    out
}

/// `validate_token`: `[\w.-]+` and nothing else.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| pystr::is_word(c) || c == '.' || c == '-')
}

/// `q_split(st, sep, maxsplit)`.
fn q_split(st: &str, sep: char, maxsplit: i64) -> Vec<&str> {
    if maxsplit == 0 {
        return vec![st];
    }
    let mut result = Vec::new();
    let mut cursor = 0;
    let mut inquote = false;
    let mut splits = 0;
    let chars: Vec<(usize, char)> = st.char_indices().collect();
    for (n, &(i, ch)) in chars.iter().enumerate() {
        if ch == '"' {
            inquote = !inquote;
        }
        if !inquote && ch == sep {
            result.push(&st[cursor..i]);
            cursor = i + ch.len_utf8();
            splits += 1;
        }
        if n + 1 == chars.len() || splits == maxsplit {
            result.push(&st[cursor..]);
            break;
        }
    }
    result
}

/// `validate_param_value(value, quoted)`.
fn param_value_ok(value: &str, quoted: bool) -> bool {
    !value.chars().any(|c| {
        matches!(c, '\x00'..='\x08' | '\x0a'..='\x1f' | '\x7f' | '"')
            || (!quoted && matches!(c, ',' | ':' | ';'))
    })
}

/// `rfc_6868_unescape`.
fn rfc_6868_unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '^' {
            match chars.peek() {
                Some('^') => {
                    chars.next();
                    out.push('^');
                }
                Some('n') => {
                    chars.next();
                    out.push('\n');
                }
                Some('\'') => {
                    chars.next();
                    out.push('"');
                }
                _ => out.push('^'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `_escape_string`.
fn escape_string(val: &str) -> String {
    val.replace('%', "%25")
        .replace("\\,", "%2C")
        .replace("\\:", "%3A")
        .replace("\\;", "%3B")
        .replace("\\\\", "%5C")
}

/// `_unescape_string`.
fn unescape_string(val: &str) -> String {
    val.replace("%2C", ",")
        .replace("%3A", ":")
        .replace("%3B", ";")
        .replace("%5C", "\\")
        .replace("%25", "%")
}

/// A parameter's value: one string or several, as `Parameters` holds it.
enum Value {
    One(String),
    Many(Vec<String>),
}

/// `Parameters.from_ical(st, strict=False)`, then the unescaped copy `raw_parts` makes, keyed
/// by `upper()`. Err for its ValueError.
fn parameters(st: &str) -> Result<Vec<(String, Value)>, ()> {
    let mut result: Vec<(String, Value)> = Vec::new();
    for param in q_split(st, ';', -1) {
        let parts = q_split(param, '=', 1);
        let [key, val] = parts.as_slice() else {
            return Err(());
        };
        if !is_token(key) {
            return Err(());
        }
        let mut vals = Vec::new();
        for v in q_split(val, ',', -1) {
            if v.starts_with('"') && v.ends_with('"') {
                let v2 = v.trim_matches('"');
                if !param_value_ok(v2, true) {
                    return Err(());
                }
                vals.push(rfc_6868_unescape(v2));
            } else {
                if !param_value_ok(v, false) {
                    return Err(());
                }
                vals.push(rfc_6868_unescape(v));
            }
        }
        let value = match vals.len() {
            0 => Value::One((*val).to_owned()),
            1 => Value::One(vals.remove(0)),
            _ => Value::Many(vals),
        };
        set(&mut result, pystr::upper(key).into_owned(), value);
    }
    let mut unescaped = Vec::new();
    for (key, value) in result {
        let value = match value {
            Value::One(s) => Value::One(unescape_string(&s)),
            Value::Many(list) => Value::Many(list.iter().map(|s| unescape_string(s)).collect()),
        };
        set(
            &mut unescaped,
            pystr::upper(&unescape_string(&key)).into_owned(),
            value,
        );
    }
    Ok(unescaped)
}

/// An ordered dict's `d[key] = value`.
fn set(dict: &mut Vec<(String, Value)>, key: String, value: Value) {
    match dict.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => dict.push((key, value)),
    }
}

/// `_strip_ows_around_delimiters(st)`.
fn strip_ows_around_delimiters(st: &str) -> String {
    if st.is_empty() || (!st.contains(' ') && !st.contains('\t')) {
        return st.to_owned();
    }
    let ows = |c: char| c == ' ' || c == '\t';
    if !st.contains('"') && !st.contains('\\') {
        // (?<![ \t])[ \t]+([;=]) -> \1, then ([;=])[ \t]+ -> \1
        let chars: Vec<char> = st.chars().collect();
        let mut first = String::with_capacity(st.len());
        let mut i = 0;
        while i < chars.len() {
            if ows(chars[i]) && (i == 0 || !ows(chars[i - 1])) {
                let mut j = i;
                while j < chars.len() && ows(chars[j]) {
                    j += 1;
                }
                if j < chars.len() && matches!(chars[j], ';' | '=') {
                    i = j;
                    continue;
                }
                first.extend(&chars[i..j]);
                i = j;
                continue;
            }
            first.push(chars[i]);
            i += 1;
        }
        let chars: Vec<char> = first.chars().collect();
        let mut second = String::with_capacity(first.len());
        let mut i = 0;
        while i < chars.len() {
            second.push(chars[i]);
            if matches!(chars[i], ';' | '=') {
                let mut j = i + 1;
                while j < chars.len() && ows(chars[j]) {
                    j += 1;
                }
                i = j;
                continue;
            }
            i += 1;
        }
        return pystr::strip(&second).to_owned();
    }
    let mut out: Vec<char> = Vec::new();
    let mut pending: Vec<char> = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut last_was_delimiter = false;
    let flush = |out: &mut Vec<char>, pending: &mut Vec<char>, last: bool| {
        if !pending.is_empty() {
            if !last {
                out.extend(pending.iter());
            }
            pending.clear();
        }
    };
    for ch in st.chars() {
        if escaped {
            flush(&mut out, &mut pending, last_was_delimiter);
            out.push(ch);
            escaped = false;
            last_was_delimiter = false;
            continue;
        }
        if ch == '\\' && !in_quotes {
            flush(&mut out, &mut pending, last_was_delimiter);
            out.push(ch);
            escaped = true;
            last_was_delimiter = false;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            flush(&mut out, &mut pending, last_was_delimiter);
            out.push(ch);
            last_was_delimiter = false;
            continue;
        }
        if !in_quotes && ows(ch) {
            pending.push(ch);
            continue;
        }
        if !in_quotes && matches!(ch, ';' | '=') {
            pending.clear();
            while out.last().is_some_and(|c| ows(*c)) {
                out.pop();
            }
            out.push(ch);
            last_was_delimiter = true;
            continue;
        }
        flush(&mut out, &mut pending, last_was_delimiter);
        out.push(ch);
        last_was_delimiter = false;
    }
    if !pending.is_empty() && !last_was_delimiter {
        out.extend(pending);
    }
    let joined: String = out.into_iter().collect();
    pystr::strip(&joined).to_owned()
}

/// `unescape_backslash`: `\\([\\,;:nN])`.
fn unescape_backslash(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    let mut chars = val.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
            && matches!(next, '\\' | ',' | ';' | ':' | 'n' | 'N')
        {
            chars.next();
            out.push(if matches!(next, 'n' | 'N') {
                '\n'
            } else {
                next
            });
            continue;
        }
        out.push(c);
    }
    out
}

/// `Contentline(line).parts()` as the finder uses it: the `FMTTYPE` parameter as `str()` gives
/// it ("" when absent) and the unescaped value, or Err for its ValueError.
pub fn parts(line: &str) -> Result<(String, String), ()> {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut name_split: Option<usize> = None;
    let mut value_split: Option<usize> = None;
    let mut in_quotes = false;
    let mut escaped = false;
    for &(i, ch) in &chars {
        if ch == '"' && !escaped {
            in_quotes = !in_quotes;
        } else if ch == '\\' && !in_quotes {
            escaped = true;
            continue;
        } else if !in_quotes && !escaped {
            if (ch == ':' || ch == ';') && name_split.is_none() {
                name_split = Some(i);
            }
            if ch == ':' && value_split.is_none() {
                value_split = Some(i);
            }
        }
        escaped = false;
    }
    // `if not value_split`: none, or at the very start
    let value_split = match value_split {
        Some(at) if at > 0 => at,
        _ => line.len(),
    };
    let name = match name_split {
        Some(at) if at > 0 => &line[..at],
        _ => line,
    };
    let name: String = pystr::strip(name)
        .chars()
        .filter(|c| *c != ' ' && *c != '\t')
        .collect();
    if !is_token(&name) {
        return Err(());
    }
    let Some(name_split) = name_split.filter(|at| *at > 0) else {
        return Err(());
    };
    let after_name = name_split + 1;
    if after_name == value_split {
        return Err(());
    }
    let raw = if after_name <= value_split {
        &line[after_name..value_split]
    } else {
        ""
    };
    let params = parameters(&escape_string(&strip_ows_around_delimiters(raw)))?;
    let fmttype = params
        .iter()
        .find(|(k, _)| k == "FMTTYPE")
        .map(|(_, v)| match v {
            Value::One(s) => s.clone(),
            Value::Many(list) => {
                let items: Vec<String> = list.iter().map(|s| ace_pycompat::repr::repr(s)).collect();
                format!("[{}]", items.join(", "))
            }
        })
        .unwrap_or_default();
    let values = line.get(value_split + 1..).unwrap_or("");
    Ok((fmttype, unescape_backslash(values)))
}

/// `unescape_char` on a str.
pub fn unescape_char(text: &str) -> String {
    text.replace("\\N", "\\n")
        .replace("\r\n", "\n")
        .replace("\\n", "\n")
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\")
}
