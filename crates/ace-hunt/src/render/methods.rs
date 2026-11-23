//! Python's methods on the values a template sees: `d.get('k')`, `seen.append(x)`,
//! `s.startswith('10.')`, `', '.join(names)` and the rest of str, list, tuple and dict.
//!
//! A method the type doesn't have is an UndefinedError, as calling the Undefined that Jinja's
//! getattr gives for it is.

use std::cmp::Ordering;

use minijinja::value::{Kwargs, Value};
use minijinja::{Error, ErrorKind, State};

use super::budget;
use super::ops::{check_strict, undefined_error};
use super::py::{
    self, DictInner, DictView, Kind, PyDict, PyList, PyTuple, ViewPart, compare, eq, int, iterate,
    kind, type_error, type_name, value_error,
};

/// Positional arguments, and keyword arguments when the call had any.
pub fn split_args(args: &[Value]) -> (Vec<Value>, Option<Kwargs>) {
    match args.last() {
        Some(last) if last.is_kwargs() => (
            args[..args.len() - 1].to_vec(),
            Kwargs::try_from(last.clone()).ok(),
        ),
        _ => (args.to_vec(), None),
    }
}

fn no_method(v: &Value, name: &str) -> Error {
    Error::new(
        ErrorKind::UndefinedError,
        format!("'{} object' has no attribute '{name}'", type_name(v)),
    )
}

fn arity(name: &str, args: &[Value], min: usize, max: usize) -> Result<(), Error> {
    if args.len() < min || args.len() > max {
        return Err(type_error(format!(
            "{name}() takes from {min} to {max} positional arguments but {} were given",
            args.len()
        )));
    }
    Ok(())
}

/// Calls `receiver.name(*args)`.
pub fn call_method(
    state: &mut State,
    receiver: &Value,
    name: &str,
    args: &[Value],
) -> Result<Value, Error> {
    if py::is_undefined(receiver) {
        return Err(undefined_error(&format!(
            "method {name} of an undefined value"
        )));
    }
    let (pos, kwargs) = split_args(args);
    match kind(receiver) {
        Kind::Dict(_) => dict_method(state, receiver, name, &pos, kwargs.as_ref()),
        Kind::List(_) => list_method(state, receiver, name, &pos),
        Kind::Tuple(t) => match name {
            "count" | "index" => seq_count_index(name, &t.0, &pos),
            _ => Err(no_method(receiver, name)),
        },
        Kind::Str(s) => str_method(s, name, &pos, kwargs.as_ref()),
        // minijinja's own objects (loop, a namespace, a macro) keep their methods; this is only
        // reached for a method they don't have
        _ => Err(Error::new(
            ErrorKind::UnknownMethod,
            format!("'{}' object has no attribute '{name}'", type_name(receiver)),
        )),
    }
}

/// `dict.update()`'s and `dict()`'s positional argument: a dict, or pairs.
pub fn update_from(state: &State, out: &mut DictInner, source: &Value) -> Result<(), Error> {
    check_strict(state, source)?;
    match kind(source) {
        Kind::Dict(d) => {
            for (k, v) in d.entries() {
                out.insert(k, v)?;
            }
        }
        _ => {
            for (i, item) in iterate(source)?.into_iter().enumerate() {
                let pair = iterate(&item).map_err(|_| {
                    type_error(format!(
                        "cannot convert dictionary update sequence element #{i} to a sequence"
                    ))
                })?;
                let [k, v] = &pair[..] else {
                    return Err(value_error(format!(
                        "dictionary update sequence element #{i} has length {}; 2 is required",
                        pair.len()
                    )));
                };
                out.insert(k.clone(), v.clone())?;
            }
        }
    }
    budget::items(out.entries().len())
}

fn dict_method(
    state: &State,
    receiver: &Value,
    name: &str,
    pos: &[Value],
    kwargs: Option<&Kwargs>,
) -> Result<Value, Error> {
    let Kind::Dict(d) = kind(receiver) else {
        unreachable!()
    };
    let view = |part| {
        Ok(Value::from_object(DictView {
            dict: d.clone(),
            part,
        }))
    };
    match name {
        "get" => {
            arity(name, pos, 1, 2)?;
            Ok(d.lookup(&pos[0])?
                .unwrap_or_else(|| pos.get(1).cloned().unwrap_or(Value::from(()))))
        }
        "items" => view(ViewPart::Items),
        "keys" => view(ViewPart::Keys),
        "values" => view(ViewPart::Values),
        "setdefault" => {
            arity(name, pos, 1, 2)?;
            if let Some(found) = d.lookup(&pos[0])? {
                return Ok(found);
            }
            let value = pos.get(1).cloned().unwrap_or(Value::from(()));
            d.with(|inner| inner.insert(pos[0].clone(), value.clone()))?;
            budget::items(d.len())?;
            Ok(value)
        }
        "update" => {
            arity(name, pos, 0, 1)?;
            let mut inner = d.snapshot();
            if let Some(source) = pos.first() {
                update_from(state, &mut inner, source)?;
            }
            if let Some(kwargs) = kwargs {
                for key in kwargs.args() {
                    inner.insert(Value::from(key), kwargs.peek::<Value>(key)?)?;
                }
            }
            d.with(|current| *current = inner);
            Ok(Value::from(()))
        }
        "pop" => {
            arity(name, pos, 1, 2)?;
            let key = py::HashKey::of(&pos[0])?;
            match d.with(|inner| inner.remove(&key)) {
                Some(v) => Ok(v),
                None => pos.get(1).cloned().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidOperation,
                        format!("KeyError: {}", py::repr(&pos[0])),
                    )
                }),
            }
        }
        "popitem" => {
            arity(name, pos, 0, 0)?;
            let last = d.entries().pop();
            match last {
                Some((k, v)) => {
                    let key = py::HashKey::of(&k)?;
                    d.with(|inner| inner.remove(&key));
                    Ok(PyTuple::of(vec![k, v]))
                }
                None => Err(Error::new(
                    ErrorKind::InvalidOperation,
                    "KeyError: 'popitem(): dictionary is empty'",
                )),
            }
        }
        "copy" => Ok(PyDict::of(d.snapshot())),
        "clear" => {
            d.with(DictInner::clear);
            Ok(Value::from(()))
        }
        _ => Err(Error::new(
            ErrorKind::UnknownMethod,
            format!("'dict' object has no attribute '{name}'"),
        )),
    }
}

fn seq_count_index(name: &str, items: &[Value], pos: &[Value]) -> Result<Value, Error> {
    arity(name, pos, 1, 1)?;
    if name == "count" {
        return Ok(int(items.iter().filter(|x| eq(x, &pos[0])).count() as i128));
    }
    items
        .iter()
        .position(|x| eq(x, &pos[0]))
        .map(|i| int(i as i128))
        .ok_or_else(|| value_error(format!("{} is not in list", py::repr(&pos[0]))))
}

fn list_method(state: &State, receiver: &Value, name: &str, pos: &[Value]) -> Result<Value, Error> {
    let Kind::List(l) = kind(receiver) else {
        unreachable!()
    };
    let none = Value::from(());
    match name {
        "append" => {
            arity(name, pos, 1, 1)?;
            l.with(|items| items.push(pos[0].clone()));
            budget::items(l.len())?;
            Ok(none)
        }
        "extend" => {
            arity(name, pos, 1, 1)?;
            check_strict(state, &pos[0])?;
            let more = iterate(&pos[0])?;
            l.with(|items| items.extend(more));
            budget::items(l.len())?;
            Ok(none)
        }
        "insert" => {
            arity(name, pos, 2, 2)?;
            let i = py::as_int(&pos[0]).ok_or_else(|| type_error("an integer is required"))?;
            l.with(|items| {
                let len = items.len() as i128;
                let at = if i < 0 { (i + len).max(0) } else { i.min(len) };
                items.insert(at as usize, pos[1].clone());
            });
            budget::items(l.len())?;
            Ok(none)
        }
        "pop" => {
            arity(name, pos, 0, 1)?;
            let i = match pos.first() {
                Some(v) => py::as_int(v).ok_or_else(|| type_error("an integer is required"))?,
                None => -1,
            };
            l.with(|items| match py::index(i, items.len()) {
                Some(at) => Ok(items.remove(at)),
                None => Err(Error::new(
                    ErrorKind::InvalidOperation,
                    if items.is_empty() {
                        "IndexError: pop from empty list"
                    } else {
                        "IndexError: pop index out of range"
                    },
                )),
            })
        }
        "remove" => {
            arity(name, pos, 1, 1)?;
            l.with(|items| match items.iter().position(|x| eq(x, &pos[0])) {
                Some(at) => {
                    items.remove(at);
                    Ok(none.clone())
                }
                None => Err(value_error("list.remove(x): x not in list")),
            })
        }
        "count" | "index" => seq_count_index(name, &l.items(), pos),
        "copy" => Ok(PyList::of(l.items())),
        "clear" => {
            l.with(Vec::clear);
            Ok(none)
        }
        "reverse" => {
            l.with(|items| items.reverse());
            Ok(none)
        }
        "sort" => {
            arity(name, pos, 0, 0)?;
            let mut items = l.items();
            sort_values(&mut items, |v| Ok(v.clone()))?;
            l.with(|current| *current = items);
            Ok(none)
        }
        _ => Err(no_method(receiver, name)),
    }
}

/// Python's stable sort with its comparisons, which fail on mixed types.
pub fn sort_values(
    items: &mut [Value],
    key: impl Fn(&Value) -> Result<Value, Error>,
) -> Result<(), Error> {
    let keys: Vec<Value> = items.iter().map(&key).collect::<Result<_, _>>()?;
    let mut order: Vec<usize> = (0..items.len()).collect();
    let mut failure = None;
    order.sort_by(|&a, &b| match compare(&keys[a], &keys[b], "<") {
        Ok(Some(o)) => o,
        Ok(None) => Ordering::Equal,
        Err(e) => {
            failure.get_or_insert(e);
            Ordering::Equal
        }
    });
    if let Some(e) = failure {
        return Err(e);
    }
    let sorted: Vec<Value> = order.into_iter().map(|i| items[i].clone()).collect();
    items.clone_from_slice(&sorted);
    Ok(())
}

/// Python's `str.isspace()` for one character.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

fn str_arg<'a>(name: &str, v: &'a Value) -> Result<&'a str, Error> {
    v.as_str().ok_or_else(|| {
        type_error(format!(
            "{name}() argument must be str, not {}",
            type_name(v)
        ))
    })
}

fn opt_str_arg<'a>(name: &str, v: Option<&'a Value>) -> Result<Option<&'a str>, Error> {
    match v {
        None => Ok(None),
        Some(v) if v.is_none() => Ok(None),
        Some(v) => str_arg(name, v).map(Some),
    }
}

fn int_arg(v: Option<&Value>, default: i128) -> Result<i128, Error> {
    match v {
        None => Ok(default),
        Some(v) if v.is_none() => Ok(default),
        Some(v) => py::as_int(v).ok_or_else(|| {
            type_error(format!(
                "'{}' object cannot be interpreted as an integer",
                type_name(v)
            ))
        }),
    }
}

fn strip(s: &str, chars: Option<&str>, left: bool, right: bool) -> String {
    let test = |c: char| match chars {
        None => is_space(c),
        Some(set) => set.contains(c),
    };
    let mut out = s;
    if left {
        out = out.trim_start_matches(test);
    }
    if right {
        out = out.trim_end_matches(test);
    }
    out.to_owned()
}

/// `str.split()` and `str.rsplit()`.
pub fn split(
    s: &str,
    sep: Option<&str>,
    maxsplit: i128,
    from_right: bool,
) -> Result<Vec<String>, Error> {
    let limit = if maxsplit < 0 {
        usize::MAX
    } else {
        maxsplit as usize
    };
    match sep {
        Some("") => Err(value_error("empty separator")),
        Some(sep) => Ok(if from_right {
            let mut parts: Vec<String> = s
                .rsplitn(limit.saturating_add(1), sep)
                .map(str::to_owned)
                .collect();
            parts.reverse();
            parts
        } else {
            s.splitn(limit.saturating_add(1), sep)
                .map(str::to_owned)
                .collect()
        }),
        None => {
            let chars: Vec<char> = s.chars().collect();
            let mut parts = Vec::new();
            if from_right {
                let mut end = chars.len();
                while parts.len() < limit {
                    while end > 0 && is_space(chars[end - 1]) {
                        end -= 1;
                    }
                    if end == 0 {
                        break;
                    }
                    let mut start = end;
                    while start > 0 && !is_space(chars[start - 1]) {
                        start -= 1;
                    }
                    parts.push(chars[start..end].iter().collect::<String>());
                    end = start;
                }
                while end > 0 && is_space(chars[end - 1]) {
                    end -= 1;
                }
                if end > 0 {
                    parts.push(chars[..end].iter().collect());
                }
                parts.reverse();
            } else {
                let mut start = 0;
                while parts.len() < limit {
                    while start < chars.len() && is_space(chars[start]) {
                        start += 1;
                    }
                    if start == chars.len() {
                        break;
                    }
                    let mut end = start;
                    while end < chars.len() && !is_space(chars[end]) {
                        end += 1;
                    }
                    parts.push(chars[start..end].iter().collect::<String>());
                    start = end;
                }
                while start < chars.len() && is_space(chars[start]) {
                    start += 1;
                }
                if start < chars.len() {
                    parts.push(chars[start..].iter().collect());
                }
            }
            Ok(parts)
        }
    }
}

/// The characters of `s` from `start` to `end` as Python's slice gives them, with the offset of
/// the first in characters.
fn window(s: &str, start: Option<&Value>, end: Option<&Value>) -> Result<(String, usize), Error> {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len() as i128;
    let clamp = |v: i128| -> usize {
        let v = if v < 0 { (v + len).max(0) } else { v.min(len) };
        v as usize
    };
    let start = clamp(int_arg(start, 0)?);
    let end = clamp(int_arg(end, len)?);
    if start > end {
        return Ok((String::new(), start));
    }
    Ok((chars[start..end].iter().collect(), start))
}

fn char_index(s: &str, byte: usize) -> usize {
    s[..byte].chars().count()
}

fn bool_value(b: bool) -> Result<Value, Error> {
    Ok(Value::from(b))
}

fn cased_all(s: &str, pred: impl Fn(char) -> bool, cased: impl Fn(char) -> bool) -> bool {
    let mut any = false;
    for c in s.chars() {
        if cased(c) {
            if !pred(c) {
                return false;
            }
            any = true;
        }
    }
    any
}

fn is_cased(c: char) -> bool {
    c.is_lowercase() || c.is_uppercase()
}

/// Python's `str.title()`: a cased character after an uncased one starts a word.
pub fn title(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut previous_cased = false;
    for c in s.chars() {
        if previous_cased {
            out.extend(c.to_lowercase());
        } else {
            out.extend(c.to_uppercase());
        }
        previous_cased = is_cased(c);
    }
    out
}

/// Python's `str.capitalize()`.
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => {
            let mut out: String = first.to_uppercase().collect();
            out.push_str(&chars.as_str().to_lowercase());
            out
        }
    }
}

fn pad(s: &str, width: i128, fill: &str, how: &str) -> Result<String, Error> {
    let mut fill_chars = fill.chars();
    let (Some(fill), None) = (fill_chars.next(), fill_chars.next()) else {
        return Err(type_error(
            "The fill character must be exactly one character long",
        ));
    };
    let len = s.chars().count() as i128;
    if width <= len {
        return Ok(s.to_owned());
    }
    let total = usize::try_from(width - len).unwrap_or(0);
    budget::string(s.len() + total * fill.len_utf8())?;
    let (left, right) = match how {
        "ljust" => (0, total),
        "rjust" => (total, 0),
        // CPython's center puts the odd character on the left when the string's length is odd
        _ => {
            let left = total / 2 + (total & usize::from(width % 2 == 1));
            let left = left.min(total);
            (left, total - left)
        }
    };
    let f = fill.to_string();
    Ok(format!("{}{s}{}", f.repeat(left), f.repeat(right)))
}

fn str_method(s: &str, name: &str, pos: &[Value], kwargs: Option<&Kwargs>) -> Result<Value, Error> {
    let kw = |key: &str| -> Option<Value> { kwargs.and_then(|k| k.peek::<Value>(key).ok()) };
    let text = |t: String| -> Result<Value, Error> {
        budget::string(t.len())?;
        Ok(Value::from(t))
    };
    match name {
        "lower" => text(s.to_lowercase()),
        "upper" => text(s.to_uppercase()),
        "casefold" => text(s.to_lowercase()),
        "swapcase" => text(
            s.chars()
                .flat_map(|c| -> Vec<char> {
                    if c.is_uppercase() {
                        c.to_lowercase().collect()
                    } else {
                        c.to_uppercase().collect()
                    }
                })
                .collect(),
        ),
        "title" => text(title(s)),
        "capitalize" => text(capitalize(s)),
        "strip" | "lstrip" | "rstrip" => {
            arity(name, pos, 0, 1)?;
            let chars = opt_str_arg(name, pos.first())?;
            text(strip(s, chars, name != "rstrip", name != "lstrip"))
        }
        "split" | "rsplit" => {
            arity(name, pos, 0, 2)?;
            let sep_value = pos.first().cloned().or_else(|| kw("sep"));
            let sep = opt_str_arg(name, sep_value.as_ref())?;
            let max_value = pos.get(1).cloned().or_else(|| kw("maxsplit"));
            let maxsplit = int_arg(max_value.as_ref(), -1)?;
            let parts = split(s, sep, maxsplit, name == "rsplit")?;
            budget::items(parts.len())?;
            Ok(PyList::of(parts.into_iter().map(Value::from).collect()))
        }
        "splitlines" => {
            arity(name, pos, 0, 1)?;
            let keep = pos.first().is_some_and(Value::is_true);
            let mut parts = Vec::new();
            let mut current = String::new();
            let mut chars = s.chars().peekable();
            while let Some(c) = chars.next() {
                let is_break = matches!(
                    c,
                    '\n' | '\r'
                        | '\x0b'
                        | '\x0c'
                        | '\x1c'
                        | '\x1d'
                        | '\x1e'
                        | '\u{85}'
                        | '\u{2028}'
                        | '\u{2029}'
                );
                if is_break {
                    if keep {
                        current.push(c);
                    }
                    if c == '\r' && chars.peek() == Some(&'\n') {
                        chars.next();
                        if keep {
                            current.push('\n');
                        }
                    }
                    parts.push(Value::from(std::mem::take(&mut current)));
                } else {
                    current.push(c);
                }
            }
            if !current.is_empty() {
                parts.push(Value::from(current));
            }
            Ok(PyList::of(parts))
        }
        "startswith" | "endswith" => {
            arity(name, pos, 1, 3)?;
            let (window, _) = window(s, pos.get(1), pos.get(2))?;
            let test = |p: &str| {
                if name == "startswith" {
                    window.starts_with(p)
                } else {
                    window.ends_with(p)
                }
            };
            match kind(&pos[0]) {
                Kind::Str(p) => bool_value(test(p)),
                Kind::Tuple(t) => {
                    for p in &t.0 {
                        if test(str_arg(name, p).map_err(|_| {
                            type_error(format!(
                                "tuple for {name} must only contain str, not {}",
                                type_name(p)
                            ))
                        })?) {
                            return bool_value(true);
                        }
                    }
                    bool_value(false)
                }
                _ => Err(type_error(format!(
                    "{name} first arg must be str or a tuple of str, not {}",
                    type_name(&pos[0])
                ))),
            }
        }
        "replace" => {
            arity(name, pos, 2, 3)?;
            let (old, new) = (str_arg(name, &pos[0])?, str_arg(name, &pos[1])?);
            let count_value = pos.get(2).cloned().or_else(|| kw("count"));
            let count = int_arg(count_value.as_ref(), -1)?;
            text(replace(s, old, new, count)?)
        }
        "join" => {
            arity(name, pos, 1, 1)?;
            let items = iterate(&pos[0])?;
            let mut parts = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                parts.push(item.as_str().ok_or_else(|| {
                    type_error(format!(
                        "sequence item {i}: expected str instance, {} found",
                        type_name(item)
                    ))
                })?);
            }
            text(parts.join(s))
        }
        "find" | "rfind" | "index" | "rindex" => {
            arity(name, pos, 1, 3)?;
            let needle = str_arg(name, &pos[0])?;
            let (hay, offset) = window(s, pos.get(1), pos.get(2))?;
            let found = if name.starts_with('r') {
                hay.rfind(needle)
            } else {
                hay.find(needle)
            };
            match found {
                Some(b) => Ok(int((offset + char_index(&hay, b)) as i128)),
                None if name.ends_with("find") => Ok(int(-1)),
                None => Err(value_error("substring not found")),
            }
        }
        "count" => {
            arity(name, pos, 1, 3)?;
            let needle = str_arg(name, &pos[0])?;
            let (hay, _) = window(s, pos.get(1), pos.get(2))?;
            let n = if needle.is_empty() {
                hay.chars().count() + 1
            } else {
                hay.matches(needle).count()
            };
            Ok(int(n as i128))
        }
        "removeprefix" => {
            arity(name, pos, 1, 1)?;
            let p = str_arg(name, &pos[0])?;
            Ok(Value::from(s.strip_prefix(p).unwrap_or(s)))
        }
        "removesuffix" => {
            arity(name, pos, 1, 1)?;
            let p = str_arg(name, &pos[0])?;
            Ok(Value::from(s.strip_suffix(p).unwrap_or(s)))
        }
        "partition" | "rpartition" => {
            arity(name, pos, 1, 1)?;
            let sep = str_arg(name, &pos[0])?;
            if sep.is_empty() {
                return Err(value_error("empty separator"));
            }
            let found = if name == "partition" {
                s.split_once(sep)
            } else {
                s.rsplit_once(sep)
            };
            let parts = match (found, name) {
                (Some((a, b)), _) => [a, sep, b],
                (None, "partition") => [s, "", ""],
                (None, _) => ["", "", s],
            };
            Ok(PyTuple::of(parts.iter().map(|p| Value::from(*p)).collect()))
        }
        "zfill" => {
            arity(name, pos, 1, 1)?;
            let width = int_arg(pos.first(), 0)?;
            let len = s.chars().count() as i128;
            if width <= len {
                return Ok(Value::from(s));
            }
            let zeros = "0".repeat(usize::try_from(width - len).unwrap_or(0));
            budget::string(zeros.len() + s.len())?;
            Ok(Value::from(match s.chars().next() {
                Some(c @ ('+' | '-')) => format!("{c}{zeros}{}", &s[1..]),
                _ => format!("{zeros}{s}"),
            }))
        }
        "ljust" | "rjust" | "center" => {
            arity(name, pos, 1, 2)?;
            let width = int_arg(pos.first(), 0)?;
            let fill = match pos.get(1) {
                Some(v) => str_arg(name, v)?,
                None => " ",
            };
            text(pad(s, width, fill, name)?)
        }
        "isdigit" | "isdecimal" | "isnumeric" => bool_value(
            !s.is_empty()
                && s.chars().all(|c| match name {
                    "isnumeric" => c.is_numeric(),
                    _ => c.is_ascii_digit() || (!c.is_ascii() && c.is_numeric()),
                }),
        ),
        "isalpha" => bool_value(!s.is_empty() && s.chars().all(char::is_alphabetic)),
        "isalnum" => bool_value(!s.is_empty() && s.chars().all(char::is_alphanumeric)),
        "isspace" => bool_value(!s.is_empty() && s.chars().all(is_space)),
        "isascii" => bool_value(s.is_ascii()),
        "islower" => bool_value(cased_all(s, char::is_lowercase, is_cased)),
        "isupper" => bool_value(cased_all(s, char::is_uppercase, is_cased)),
        "istitle" => bool_value(!s.is_empty() && title(s) == s && s.chars().any(is_cased)),
        "format" | "format_map" => Err(Error::new(
            ErrorKind::InvalidOperation,
            "str.format isn't ported (ace-rs); no hunt template uses it",
        )),
        _ => Err(Error::new(
            ErrorKind::UndefinedError,
            format!("'str object' has no attribute '{name}'"),
        )),
    }
}

/// `str.replace(old, new, count)`.
pub fn replace(s: &str, old: &str, new: &str, count: i128) -> Result<String, Error> {
    let out = if count < 0 {
        s.replace(old, new)
    } else {
        s.replacen(old, new, usize::try_from(count).unwrap_or(usize::MAX))
    };
    budget::string(out.len())?;
    Ok(out)
}
