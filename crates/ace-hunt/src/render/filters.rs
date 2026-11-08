//! Jinja2 3.1's filters and tests, ported from `jinja2/filters.py` and `jinja2/tests.py` with
//! their Python semantics, and ace3's `fromjson` (`saq/query/summary_detail_rendering.py`).
//!
//! Each filter binds its arguments as the Python function does, by position or keyword. A filter
//! that returns a generator in Jinja (`map`, `select`, `reverse`, `unique`, `batch`, ...) returns a
//! list here: iterating, joining or `|list` give the same, and only printing one directly differs
//! (Python prints `<generator object ...>`).
//!
//! Not ported, because no hunt template uses them and each is a library of its own: `format`
//! (printf formatting), `groupby`, `pprint`, `random`, `striptags`, `urlize`, `wordwrap` and
//! `xmlattr`. A template using one fails to render, as one naming an unknown filter does.

use minijinja::value::{Kwargs, Rest, Value};
use minijinja::{Error, ErrorKind, State};

use super::budget;
use super::json;
use super::methods::{self, capitalize, is_space, sort_values};
use super::ops::{self, check_strict, compare_op, contains, getitem, to_str};
use super::py::{
    self, DictInner, HashKey, Kind, Num, PyDict, PyList, PyTuple, int, iterate, kind, number,
    str_of, type_error, type_name,
};

pub type FilterFn = fn(&mut State, Rest<Value>, Kwargs) -> Result<Value, Error>;
pub type TestFn = fn(&mut State, Rest<Value>, Kwargs) -> Result<bool, Error>;

/// The filters a template has.
pub fn filters() -> &'static [(&'static str, FilterFn)] {
    &[
        ("abs", abs),
        ("attr", attr),
        ("batch", batch),
        ("capitalize", capitalize_filter),
        ("center", center),
        ("count", length),
        ("d", default),
        ("default", default),
        ("dictsort", dictsort),
        ("e", escape),
        ("escape", escape),
        ("filesizeformat", filesizeformat),
        ("first", first),
        ("float", float),
        ("forceescape", forceescape),
        ("fromjson", fromjson),
        ("indent", indent),
        ("int", int_filter),
        ("items", items),
        ("join", join),
        ("last", last),
        ("length", length),
        ("list", list),
        ("lower", lower),
        ("map", map),
        ("max", max),
        ("min", min),
        ("reject", reject),
        ("rejectattr", rejectattr),
        ("replace", replace),
        ("reverse", reverse),
        ("round", round),
        ("safe", safe),
        ("select", select),
        ("selectattr", selectattr),
        ("slice", slice),
        ("sort", sort),
        ("string", string),
        ("sum", sum),
        ("title", title_filter),
        ("tojson", tojson),
        ("trim", trim),
        ("truncate", truncate),
        ("unique", unique),
        ("upper", upper),
        ("urlencode", urlencode),
        ("wordcount", wordcount),
    ]
}

/// The tests a template has.
pub fn tests() -> &'static [(&'static str, TestFn)] {
    &[
        ("odd", odd),
        ("even", even),
        ("divisibleby", divisibleby),
        ("defined", defined),
        ("undefined", undefined),
        ("filter", is_filter),
        ("test", is_test),
        ("none", is_none),
        ("boolean", boolean),
        ("false", is_false),
        ("true", is_true),
        ("integer", integer),
        ("float", is_float),
        ("lower", is_lower),
        ("upper", is_upper),
        ("string", is_string),
        ("mapping", mapping),
        ("number", is_number),
        ("sequence", sequence),
        ("iterable", iterable),
        ("callable", callable),
        ("sameas", sameas),
        ("escaped", escaped),
        ("in", is_in),
        ("==", t_eq),
        ("eq", t_eq),
        ("equalto", t_eq),
        ("!=", t_ne),
        ("ne", t_ne),
        (">", t_gt),
        ("gt", t_gt),
        ("greaterthan", t_gt),
        (">=", t_ge),
        ("ge", t_ge),
        ("<", t_lt),
        ("lt", t_lt),
        ("lessthan", t_lt),
        ("<=", t_le),
        ("le", t_le),
    ]
}

/// A Python function's arguments bound by position, then keyword; `None` where not given.
struct Bound(Vec<Option<Value>>);

impl Bound {
    fn new(kwargs: &Kwargs, name: &str, args: &[Value], params: &[&str]) -> Result<Bound, Error> {
        let pos = args;
        if pos.len() > params.len() {
            return Err(type_error(format!(
                "{name}() takes {} positional arguments but {} were given",
                params.len(),
                pos.len()
            )));
        }
        let mut out: Vec<Option<Value>> = params.iter().map(|_| None).collect();
        for (i, v) in pos.iter().enumerate() {
            out[i] = Some(v.clone());
        }
        {
            let keys: Vec<String> = kwargs.args().map(str::to_owned).collect();
            for key in &keys {
                let key = key.as_str();
                let Some(i) = params.iter().position(|p| *p == key) else {
                    return Err(type_error(format!(
                        "{name}() got an unexpected keyword argument '{key}'"
                    )));
                };
                if out[i].is_some() {
                    return Err(type_error(format!(
                        "{name}() got multiple values for argument '{key}'"
                    )));
                }
                out[i] = Some(kwargs.get::<Value>(key)?);
            }
        }
        if out[0].is_none() {
            return Err(type_error(format!(
                "{name}() missing 1 required positional argument: '{}'",
                params[0]
            )));
        }
        Ok(Bound(out))
    }

    fn value(&self) -> &Value {
        self.0[0].as_ref().expect("bound")
    }

    fn get(&self, i: usize) -> Option<&Value> {
        self.0[i].as_ref()
    }

    /// An argument, or the default when it's not given.
    fn or(&self, i: usize, default: Value) -> Value {
        self.0[i].clone().unwrap_or(default)
    }

    fn flag(&self, i: usize) -> bool {
        self.0[i].as_ref().is_some_and(Value::is_true)
    }
}

fn none() -> Value {
    Value::from(())
}

/// Iterates the value a filter was given, which an undefined one allows only outside
/// StrictUndefined.
fn items_of(state: &State, v: &Value) -> Result<Vec<Value>, Error> {
    check_strict(state, v)?;
    iterate(v)
}

fn str_value(s: String) -> Result<Value, Error> {
    budget::string(s.len())?;
    Ok(Value::from(s))
}

/// `soft_str()`: `str()` of anything.
fn soft(state: &State, v: &Value) -> Result<String, Error> {
    to_str(state, v)
}

/// Python's truthiness, which fails on an undefined value under StrictUndefined.
fn truthy(state: &State, v: &Value) -> Result<bool, Error> {
    check_strict(state, v)?;
    Ok(v.is_true())
}

/// `environment.getitem` for each part of `a.b.0`, as `make_attrgetter` does.
fn attribute_parts(attribute: &Value) -> Vec<Value> {
    match attribute.as_str() {
        Some(s) => s
            .split('.')
            .map(|part| {
                if !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) {
                    part.parse::<i128>()
                        .map(int)
                        .unwrap_or_else(|_| Value::from(part))
                } else {
                    Value::from(part)
                }
            })
            .collect(),
        None if attribute.is_none() => Vec::new(),
        None => vec![attribute.clone()],
    }
}

fn get_path(state: &State, item: &Value, parts: &[Value]) -> Result<Value, Error> {
    let mut v = item.clone();
    for part in parts {
        v = getitem(state, v, part.clone())?;
    }
    Ok(v)
}

fn ignore_case(v: Value) -> Value {
    match kind(&v) {
        Kind::Str(s) => Value::from(s.to_lowercase()),
        _ => v,
    }
}

fn abs(_: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_abs", &args, &["x"])?;
    let v = b.value();
    match number(&kind(v)) {
        Some(Num::Int(i)) => Ok(int(i.checked_abs().unwrap_or(i128::MAX))),
        Some(Num::Float(f)) => Ok(Value::from(f.abs())),
        None => Err(type_error(format!(
            "bad operand type for abs(): '{}'",
            type_name(v)
        ))),
    }
}

fn attr(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_attr", &args, &["obj", "name"])?;
    // do_attr is getattr alone, with no item lookup after it
    let name = soft(state, &b.or(1, Value::from("")))?;
    let _ = state;
    Ok(ops::python_attr(b.value(), &name).unwrap_or(Value::UNDEFINED))
}

fn batch(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "do_batch",
        &args,
        &["value", "linecount", "fill_with"],
    )?;
    let n = b
        .get(1)
        .and_then(py::as_int)
        .ok_or_else(|| type_error("batch() needs an integer linecount"))?;
    let fill = b.or(2, none());
    let mut out = Vec::new();
    let mut tmp = Vec::new();
    for item in items_of(state, b.value())? {
        if tmp.len() as i128 == n {
            out.push(PyList::of(std::mem::take(&mut tmp)));
        }
        tmp.push(item);
    }
    if !tmp.is_empty() {
        if !fill.is_none() {
            while (tmp.len() as i128) < n {
                tmp.push(fill.clone());
            }
        }
        out.push(PyList::of(tmp));
    }
    Ok(PyList::of(out))
}

fn capitalize_filter(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_capitalize", &args, &["s"])?;
    str_value(capitalize(&soft(state, b.value())?))
}

fn center(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_center", &args, &["value", "width"])?;
    let s = soft(state, b.value())?;
    let width = b.or(1, int(80));
    methods::call_method(state, &Value::from(s), "center", &[width])
}

fn default(_: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "do_default",
        &args,
        &["value", "default_value", "boolean"],
    )?;
    let v = b.value();
    if py::is_undefined(v) || (b.flag(2) && !v.is_true()) {
        Ok(b.or(1, Value::from("")))
    } else {
        Ok(v.clone())
    }
}

fn dictsort(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "do_dictsort",
        &args,
        &["value", "case_sensitive", "by", "reverse"],
    )?;
    let pos = match b.get(2).map(str_of).as_deref() {
        None | Some("key") => 0,
        Some("value") => 1,
        Some(_) => {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "FilterArgumentError: You can only sort by either \"key\" or \"value\"",
            ));
        }
    };
    check_strict(state, b.value())?;
    let Kind::Dict(d) = kind(b.value()) else {
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            format!(
                "AttributeError: '{}' object has no attribute 'items'",
                type_name(b.value())
            ),
        ));
    };
    let mut pairs: Vec<Value> = d
        .entries()
        .into_iter()
        .map(|(k, v)| PyTuple::of(vec![k, v]))
        .collect();
    let case_sensitive = b.flag(1);
    sorted(&mut pairs, b.flag(3), |pair| {
        let part = iterate(pair)?.remove(pos);
        Ok(if case_sensitive {
            part
        } else {
            ignore_case(part)
        })
    })?;
    Ok(PyList::of(pairs))
}

/// `sorted(items, key=key, reverse=reverse)`, stable either way.
fn sorted(
    items: &mut [Value],
    reverse: bool,
    key: impl Fn(&Value) -> Result<Value, Error>,
) -> Result<(), Error> {
    if reverse {
        items.reverse();
        sort_values(items, key)?;
        items.reverse();
        Ok(())
    } else {
        sort_values(items, key)
    }
}

/// markupsafe's `escape` of a string.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn escape(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "escape", &args, &["s"])?;
    let v = b.value();
    if v.is_safe() {
        return Ok(v.clone());
    }
    let escaped = html_escape(&soft(state, v)?);
    budget::string(escaped.len())?;
    Ok(Value::from_safe_string(escaped))
}

fn forceescape(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_forceescape", &args, &["value"])?;
    let escaped = html_escape(&soft(state, b.value())?);
    budget::string(escaped.len())?;
    Ok(Value::from_safe_string(escaped))
}

fn filesizeformat(_: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_filesizeformat", &args, &["value", "binary"])?;
    let bytes = match number(&kind(b.value())) {
        Some(Num::Int(i)) => i as f64,
        Some(Num::Float(f)) => f,
        None => match b.value().as_str().map(str::trim).map(str::parse::<f64>) {
            Some(Ok(f)) => f,
            _ => return Err(py::value_error("could not convert string to float")),
        },
    };
    let binary = b.flag(1);
    let base: f64 = if binary { 1024.0 } else { 1000.0 };
    let prefixes = if binary {
        ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]
    } else {
        ["kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    };
    if bytes == 1.0 {
        return Ok(Value::from("1 Byte"));
    }
    if bytes < base {
        return Ok(Value::from(format!("{} Bytes", bytes as i128)));
    }
    let mut unit = base;
    let mut text = String::new();
    for (i, prefix) in prefixes.iter().enumerate() {
        unit = base.powi(i as i32 + 2);
        if bytes < unit {
            text = format!("{:.1} {prefix}", base * bytes / unit);
            break;
        }
    }
    if text.is_empty() {
        text = format!("{:.1} {}", base * bytes / unit, prefixes[7]);
    }
    Ok(Value::from(text))
}

fn first(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_first", &args, &["seq"])?;
    Ok(items_of(state, b.value())?
        .into_iter()
        .next()
        .unwrap_or(Value::UNDEFINED))
}

fn last(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_last", &args, &["seq"])?;
    let v = b.value();
    check_strict(state, v)?;
    if py::is_undefined(v) {
        // reversed() works on Undefined, which has a length and items, and gives nothing
        return Ok(Value::UNDEFINED);
    }
    Ok(iterate(v)?.pop().unwrap_or(Value::UNDEFINED))
}

/// Python's `float()` of a string: surrounding whitespace, underscores between digits, and
/// `nan`, `inf` and `infinity` in any case.
pub fn parse_float(s: &str) -> Option<f64> {
    let t = s.trim_matches(is_space);
    if t.is_empty() {
        return None;
    }
    let bytes = t.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c == b'_' {
            let before = i.checked_sub(1).map(|j| bytes[j]);
            let after = bytes.get(i + 1);
            if !before.is_some_and(|b| b.is_ascii_digit()) || !after.is_some_and(u8::is_ascii_digit)
            {
                return None;
            }
        }
    }
    let cleaned: String = t.chars().filter(|&c| c != '_').collect();
    let lower = cleaned.to_ascii_lowercase();
    let body = lower.trim_start_matches(['+', '-']);
    if body.len() + 1 < lower.len() {
        return None;
    }
    if ["nan", "inf", "infinity"].contains(&body) {
        let f = if body == "nan" {
            f64::NAN
        } else {
            f64::INFINITY
        };
        return Some(if lower.starts_with('-') { -f } else { f });
    }
    if !body
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | '+' | '-'))
    {
        return None;
    }
    cleaned.parse::<f64>().ok()
}

/// Python's `int()` of a string in a base from 2 to 36.
pub fn parse_int(s: &str, base: u32) -> Option<i128> {
    let t = s.trim_matches(is_space);
    let (neg, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let body = match base {
        16 => body
            .strip_prefix("0x")
            .or_else(|| body.strip_prefix("0X"))
            .unwrap_or(body),
        8 => body
            .strip_prefix("0o")
            .or_else(|| body.strip_prefix("0O"))
            .unwrap_or(body),
        2 => body
            .strip_prefix("0b")
            .or_else(|| body.strip_prefix("0B"))
            .unwrap_or(body),
        _ => body,
    };
    if body.is_empty() || body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    let digits: String = body.chars().filter(|&c| c != '_').collect();
    if !digits.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let v = i128::from_str_radix(&digits, base).ok()?;
    Some(if neg { -v } else { v })
}

fn float(_: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_float", &args, &["value", "default"])?;
    let default = b.or(1, Value::from(0.0));
    if py::is_undefined(b.value()) {
        // Undefined's __float__ raises
        return Err(ops::undefined_error("a value"));
    }
    Ok(match kind(b.value()) {
        Kind::Bool(x) => Value::from(f64::from(u8::from(x))),
        Kind::Int(i) => Value::from(i as f64),
        Kind::Float(f) => Value::from(f),
        Kind::Str(s) => parse_float(s).map(Value::from).unwrap_or(default),
        _ => default,
    })
}

fn int_filter(_: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_int", &args, &["value", "default", "base"])?;
    let default = b.or(1, int(0));
    if py::is_undefined(b.value()) {
        // Undefined's __int__ raises
        return Err(ops::undefined_error("a value"));
    }
    let base = b.get(2).and_then(py::as_int).unwrap_or(10);
    let from_float = |f: f64| -> Result<Value, Error> {
        if f.is_nan() {
            Ok(default.clone())
        } else if f.is_infinite() {
            Err(Error::new(
                ErrorKind::InvalidOperation,
                "OverflowError: cannot convert float infinity to integer",
            ))
        } else {
            Ok(int(f.trunc() as i128))
        }
    };
    match kind(b.value()) {
        Kind::Bool(x) => Ok(int(i128::from(x))),
        Kind::Int(i) => Ok(int(i)),
        Kind::Float(f) => from_float(f),
        Kind::Str(s) => {
            if let Some(i) = u32::try_from(base)
                .ok()
                .filter(|b| (2..=36).contains(b))
                .and_then(|b| parse_int(s, b))
            {
                return Ok(int(i));
            }
            match parse_float(s) {
                Some(f) if f.is_infinite() => Ok(default),
                Some(f) => from_float(f),
                None => Ok(default),
            }
        }
        _ => Ok(default),
    }
}

fn fromjson(_: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "_safe_fromjson", &args, &["value"])?;
    let empty = || PyDict::of(DictInner::default());
    Ok(match b.value().as_str() {
        Some(text) => match json::loads(text) {
            Ok(v) => json::to_template(&v),
            Err(_) => empty(),
        },
        None => empty(),
    })
}

fn splitlines(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(
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
        ) {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn indent(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "do_indent",
        &args,
        &["s", "width", "first", "blank"],
    )?;
    let safe = b.value().is_safe();
    if py::is_undefined(b.value()) {
        // `s += newline` on an Undefined raises
        return Err(ops::undefined_error("a value"));
    }
    let mut s = soft(state, b.value())?;
    let unit = match b.get(1) {
        Some(w) if w.as_str().is_some() => w.as_str().unwrap_or("").to_owned(),
        Some(w) => " ".repeat(usize::try_from(py::as_int(w).unwrap_or(4).max(0)).unwrap_or(0)),
        None => "    ".to_owned(),
    };
    s.push('\n');
    let lines = splitlines(&s);
    let mut rv = if b.flag(3) {
        lines.join(&format!("\n{unit}"))
    } else {
        let mut it = lines.into_iter();
        let mut rv = it.next().unwrap_or_default();
        let rest: Vec<String> = it
            .map(|line| {
                if line.is_empty() {
                    line
                } else {
                    format!("{unit}{line}")
                }
            })
            .collect();
        if !rest.is_empty() {
            rv.push('\n');
            rv.push_str(&rest.join("\n"));
        }
        rv
    };
    if b.flag(2) {
        rv = format!("{unit}{rv}");
    }
    budget::string(rv.len())?;
    Ok(if safe {
        Value::from_safe_string(rv)
    } else {
        Value::from(rv)
    })
}

fn items(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_items", &args, &["value"])?;
    let v = b.value();
    if py::is_undefined(v) {
        return Ok(PyList::of(Vec::new()));
    }
    check_strict(state, v)?;
    match kind(v) {
        Kind::Dict(d) => Ok(PyList::of(
            d.entries()
                .into_iter()
                .map(|(k, v)| PyTuple::of(vec![k, v]))
                .collect(),
        )),
        _ => Err(type_error("Can only get item pairs from a mapping.")),
    }
}

fn join(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "sync_do_join", &args, &["value", "d", "attribute"])?;
    let sep = soft(state, &b.or(1, Value::from("")))?;
    let mut values = items_of(state, b.value())?;
    if let Some(attribute) = b.get(2).filter(|a| !a.is_none()) {
        let parts = attribute_parts(attribute);
        values = values
            .iter()
            .map(|v| get_path(state, v, &parts))
            .collect::<Result<_, _>>()?;
    }
    let mut out = String::new();
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push_str(&sep);
        }
        out.push_str(&soft(state, v)?);
        budget::string(out.len())?;
    }
    Ok(Value::from(out))
}

fn length(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "sync_do_count", &args, &["value"])?;
    let v = b.value();
    check_strict(state, v)?;
    let n = match kind(v) {
        Kind::Undefined => 0,
        Kind::Str(s) => s.chars().count(),
        Kind::List(l) => l.len(),
        Kind::Tuple(t) => t.0.len(),
        Kind::Dict(d) => d.len(),
        Kind::View(view) => view.dict.len(),
        Kind::Range(r) => r.len(),
        Kind::Seq | Kind::Map => v.len().unwrap_or(0),
        _ => {
            return Err(type_error(format!(
                "object of type '{}' has no len()",
                type_name(v)
            )));
        }
    };
    Ok(int(n as i128))
}

fn list(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "sync_do_list", &args, &["value"])?;
    Ok(PyList::of(items_of(state, b.value())?))
}

fn lower(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_lower", &args, &["s"])?;
    str_value(soft(state, b.value())?.to_lowercase())
}

fn upper(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_upper", &args, &["s"])?;
    str_value(soft(state, b.value())?.to_uppercase())
}

fn title_filter(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_title", &args, &["s"])?;
    // Jinja's own title: a word starts after `-`, whitespace or an opening bracket
    let s = soft(state, b.value())?;
    let mut out = String::with_capacity(s.len());
    let mut start = true;
    for c in s.chars() {
        if c == '-' || is_space(c) || matches!(c, '(' | '{' | '[' | '<') {
            out.push(c);
            start = true;
        } else if start {
            out.extend(c.to_uppercase());
            start = false;
        } else {
            out.extend(c.to_lowercase());
        }
    }
    str_value(out)
}

fn apply_filter(state: &mut State, name: &str, args: &[Value]) -> Result<Value, Error> {
    match state.apply_filter(name, args) {
        Err(e) if e.kind() == ErrorKind::UnknownFilter => Err(Error::new(
            ErrorKind::UnknownFilter,
            format!("TemplateRuntimeError: No filter named '{name}' found."),
        )),
        other => other,
    }
}

fn perform_test(state: &mut State, name: &str, args: &[Value]) -> Result<bool, Error> {
    match state.perform_test(name, args) {
        Err(e) if e.kind() == ErrorKind::UnknownTest => Err(Error::new(
            ErrorKind::UnknownTest,
            format!("TemplateRuntimeError: No test named '{name}' found."),
        )),
        other => other,
    }
}

/// `prepare_map`: a filter by name applied to each item, or an attribute of each.
fn map(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let Some(value) = args.first() else {
        return Err(type_error("map() missing its value"));
    };
    if !truthy(state, value)? {
        return Ok(PyList::of(Vec::new()));
    }
    let pos = &args[1..];
    let mut out = Vec::new();
    if pos.is_empty() && kwargs.has("attribute") {
        let attribute: Value = kwargs.get("attribute")?;
        let default: Option<Value> = kwargs.get::<Option<Value>>("default")?;
        for key in kwargs.args() {
            if key != "attribute" && key != "default" {
                return Err(Error::new(
                    ErrorKind::InvalidOperation,
                    format!("FilterArgumentError: Unexpected keyword argument '{key}'"),
                ));
            }
        }
        let parts = attribute_parts(&attribute);
        for item in iterate(value)? {
            let mut v = item;
            for part in &parts {
                v = getitem(state, v, part.clone())?;
                if let Some(d) = default.as_ref().filter(|d| !d.is_none())
                    && py::is_undefined(&v)
                {
                    v = d.clone();
                }
            }
            out.push(v);
        }
        return Ok(PyList::of(out));
    }
    let Some(name) = pos.first().map(str_of) else {
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            "FilterArgumentError: map requires a filter argument",
        ));
    };
    let mut rest: Vec<Value> = pos[1..].to_vec();
    if let Some(kwargs) = forward(&kwargs)? {
        rest.push(kwargs);
    }
    for item in iterate(value)? {
        let mut call = vec![item];
        call.extend(rest.iter().cloned());
        out.push(apply_filter(state, &name, &call)?);
    }
    Ok(PyList::of(out))
}

/// Keyword arguments passed on to another filter or test, marked used here.
fn forward(kwargs: &Kwargs) -> Result<Option<Value>, Error> {
    let keys: Vec<String> = kwargs.args().map(str::to_owned).collect();
    if keys.is_empty() {
        return Ok(None);
    }
    let mut pairs = Vec::with_capacity(keys.len());
    for key in keys {
        let v: Value = kwargs.get(&key)?;
        pairs.push((key, v));
    }
    Ok(Some(Value::from(pairs.into_iter().collect::<Kwargs>())))
}

fn select_or_reject(
    state: &mut State,
    args: &[Value],
    kwargs: &Kwargs,
    reject: bool,
    lookup_attr: bool,
) -> Result<Value, Error> {
    let Some(value) = args.first() else {
        return Err(type_error("select() missing its value"));
    };
    if !truthy(state, value)? {
        return Ok(PyList::of(Vec::new()));
    }
    let pos = &args[1..];
    let (parts, off) = if lookup_attr {
        let attr = pos.first().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidOperation,
                "FilterArgumentError: Missing parameter for attribute name",
            )
        })?;
        (Some(attribute_parts(attr)), 1)
    } else {
        (None, 0)
    };
    let test = pos.get(off).map(str_of);
    let mut test_args: Vec<Value> = pos
        .get(off + 1..)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    if let Some(kwargs) = forward(kwargs)? {
        test_args.push(kwargs);
    }
    let mut out = Vec::new();
    for item in iterate(value)? {
        let subject = match &parts {
            Some(parts) => get_path(state, &item, parts)?,
            None => item.clone(),
        };
        let passed = match &test {
            Some(name) => {
                let mut call = vec![subject];
                call.extend(test_args.iter().cloned());
                perform_test(state, name, &call)?
            }
            None => truthy(state, &subject)?,
        };
        if passed != reject {
            out.push(item);
        }
    }
    Ok(PyList::of(out))
}

fn select(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    select_or_reject(state, &args, &kwargs, false, false)
}

fn reject(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    select_or_reject(state, &args, &kwargs, true, false)
}

fn selectattr(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    select_or_reject(state, &args, &kwargs, false, true)
}

fn rejectattr(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    select_or_reject(state, &args, &kwargs, true, true)
}

fn min_or_max(
    state: &mut State,
    args: &[Value],
    kwargs: &Kwargs,
    name: &str,
    want: std::cmp::Ordering,
) -> Result<Value, Error> {
    let b = Bound::new(
        kwargs,
        name,
        args,
        &["value", "case_sensitive", "attribute"],
    )?;
    let items = items_of(state, b.value())?;
    if items.is_empty() {
        return Ok(Value::UNDEFINED);
    }
    let parts = attribute_parts(&b.or(2, none()));
    let case_sensitive = b.flag(1);
    let key = |item: &Value| -> Result<Value, Error> {
        let v = get_path(state, item, &parts)?;
        Ok(if case_sensitive { v } else { ignore_case(v) })
    };
    let mut best = items[0].clone();
    let mut best_key = key(&best)?;
    for item in &items[1..] {
        let k = key(item)?;
        if py::compare(&k, &best_key, if want.is_gt() { ">" } else { "<" })? == Some(want) {
            best = item.clone();
            best_key = k;
        }
    }
    Ok(best)
}

fn max(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    min_or_max(state, &args, &kwargs, "do_max", std::cmp::Ordering::Greater)
}

fn min(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    min_or_max(state, &args, &kwargs, "do_min", std::cmp::Ordering::Less)
}

fn replace(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_replace", &args, &["s", "old", "new", "count"])?;
    let s = soft(state, b.value())?;
    let old = soft(state, &b.or(1, Value::UNDEFINED))?;
    let new = soft(state, &b.or(2, Value::UNDEFINED))?;
    if b.get(1).is_none() || b.get(2).is_none() {
        return Err(type_error("do_replace() missing required arguments"));
    }
    let count = match b.get(3) {
        None => -1,
        Some(c) if c.is_none() => -1,
        Some(c) => py::as_int(c).ok_or_else(|| {
            type_error(format!(
                "'{}' object cannot be interpreted as an integer",
                type_name(c)
            ))
        })?,
    };
    Ok(Value::from(methods::replace(&s, &old, &new, count)?))
}

fn reverse(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_reverse", &args, &["value"])?;
    let v = b.value();
    if let Some(s) = v.as_str() {
        return Ok(Value::from(s.chars().rev().collect::<String>()));
    }
    let mut items = items_of(state, v)?;
    items.reverse();
    Ok(PyList::of(items))
}

fn round(_: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "do_round",
        &args,
        &["value", "precision", "method"],
    )?;
    let precision = b.get(1).and_then(py::as_int).unwrap_or(0);
    let method = b.get(2).map(str_of).unwrap_or_else(|| "common".to_owned());
    let x = match number(&kind(b.value())) {
        Some(n) => n,
        None => {
            return Err(type_error(format!(
                "type {} doesn't define __round__ method",
                type_name(b.value())
            )));
        }
    };
    let scale = 10f64.powi(i32::try_from(precision).unwrap_or(0));
    match method.as_str() {
        "common" => Ok(match x {
            Num::Int(i) if precision >= 0 => int(i),
            Num::Int(i) => {
                int(((i as f64 / (1.0 / scale)).round_ties_even() * (1.0 / scale)) as i128)
            }
            Num::Float(f) if precision >= 0 => {
                // Python rounds the float's exact value, as formatting to a precision does
                let digits = usize::try_from(precision).unwrap_or(0).min(400);
                let r: f64 = format!("{f:.digits$}").parse().unwrap_or(f);
                Value::from(r)
            }
            Num::Float(f) => {
                let r = (f / (1.0 / scale)).round_ties_even() * (1.0 / scale);
                Value::from(if r.is_finite() { r } else { f })
            }
        }),
        "ceil" | "floor" => {
            let f = match x {
                Num::Int(i) => i as f64,
                Num::Float(f) => f,
            };
            let scaled = f * scale;
            let r = if method == "ceil" {
                scaled.ceil()
            } else {
                scaled.floor()
            };
            Ok(Value::from(r / scale))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidOperation,
            "FilterArgumentError: method must be common, ceil or floor",
        )),
    }
}

fn safe(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_mark_safe", &args, &["value"])?;
    Ok(Value::from_safe_string(soft(state, b.value())?))
}

fn slice(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "sync_do_slice",
        &args,
        &["value", "slices", "fill_with"],
    )?;
    let seq = items_of(state, b.value())?;
    let slices = b
        .get(1)
        .and_then(py::as_int)
        .ok_or_else(|| type_error("slice() needs an integer count"))?;
    if slices <= 0 {
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            "ZeroDivisionError: integer division or modulo by zero",
        ));
    }
    let fill = b.or(2, none());
    let len = seq.len() as i128;
    let per = len / slices;
    let extra = len % slices;
    let mut offset = 0;
    let mut out = Vec::new();
    for n in 0..slices {
        let start = offset + n * per;
        if n < extra {
            offset += 1;
        }
        let end = offset + (n + 1) * per;
        let mut tmp: Vec<Value> = seq[start as usize..end as usize].to_vec();
        if !fill.is_none() && n >= extra {
            tmp.push(fill.clone());
        }
        out.push(PyList::of(tmp));
    }
    Ok(PyList::of(out))
}

fn sort(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "do_sort",
        &args,
        &["value", "reverse", "case_sensitive", "attribute"],
    )?;
    let mut items = items_of(state, b.value())?;
    let case_sensitive = b.flag(2);
    // make_multi_attrgetter: a key is a list of each comma-separated attribute's value
    let attributes: Vec<Vec<Value>> = match b.get(3).filter(|a| !a.is_none()) {
        Some(a) => match a.as_str() {
            Some(s) => s
                .split(',')
                .map(|p| attribute_parts(&Value::from(p)))
                .collect(),
            None => vec![vec![a.clone()]],
        },
        None => vec![Vec::new()],
    };
    sorted(&mut items, b.flag(1), |item| {
        let mut key = Vec::with_capacity(attributes.len());
        for parts in &attributes {
            let v = get_path(state, item, parts)?;
            key.push(if case_sensitive { v } else { ignore_case(v) });
        }
        Ok(PyList::of(key))
    })?;
    Ok(PyList::of(items))
}

fn string(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_string", &args, &["value"])?;
    let v = b.value();
    if v.is_safe() {
        return Ok(v.clone());
    }
    Ok(Value::from(soft(state, v)?))
}

fn sum(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "sync_do_sum",
        &args,
        &["iterable", "attribute", "start"],
    )?;
    let mut items = items_of(state, b.value())?;
    if let Some(attribute) = b.get(1).filter(|a| !a.is_none()) {
        let parts = attribute_parts(attribute);
        items = items
            .iter()
            .map(|v| get_path(state, v, &parts))
            .collect::<Result<_, _>>()?;
    }
    let mut total = b.or(2, int(0));
    if matches!(kind(&total), Kind::Str(_)) {
        return Err(type_error(
            "sum() can't sum strings [use ''.join(seq) instead]",
        ));
    }
    for item in items {
        total = ops::add(state, Rest(vec![total, item]))?;
    }
    Ok(total)
}

fn tojson(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_tojson", &args, &["value", "indent"])?;
    let indent = match b.get(1) {
        None => None,
        Some(v) if v.is_none() => None,
        Some(v) => Some(match kind(v) {
            Kind::Str(s) => s.to_owned(),
            Kind::Int(i) => " ".repeat(usize::try_from(i.max(0)).unwrap_or(0)),
            _ => return Err(type_error("indent must be an int or a str")),
        }),
    };
    let _ = state;
    let text = json::dumps_html_safe(b.value(), indent.as_deref())?;
    budget::string(text.len())?;
    Ok(Value::from_safe_string(text))
}

fn trim(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_trim", &args, &["value", "chars"])?;
    let s = soft(state, b.value())?;
    let chars = b.get(1).filter(|c| !c.is_none()).map(str_of);
    let test = |c: char| match &chars {
        None => is_space(c),
        Some(set) => set.contains(c),
    };
    Ok(Value::from(s.trim_matches(test).to_owned()))
}

fn truncate(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "do_truncate",
        &args,
        &["s", "length", "killwords", "end", "leeway"],
    )?;
    let length = b.get(1).and_then(py::as_int).unwrap_or(255);
    let end = match b.get(2 + 1) {
        Some(e) => soft(state, e)?,
        None => "...".to_owned(),
    };
    let leeway = b.get(4).and_then(py::as_int).unwrap_or(5);
    let end_len = end.chars().count() as i128;
    if length < end_len {
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            format!("AssertionError: expected length >= {end_len}, got {length}"),
        ));
    }
    if leeway < 0 {
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            format!("AssertionError: expected leeway >= 0, got {leeway}"),
        ));
    }
    let v = b.value();
    check_strict(state, v)?;
    let s = match kind(v) {
        Kind::Undefined => return Ok(v.clone()),
        Kind::Str(s) => s,
        _ => {
            return Err(type_error(format!(
                "object of type '{}' has no len()",
                type_name(v)
            )));
        }
    };
    let chars: Vec<char> = s.chars().collect();
    if chars.len() as i128 <= length + leeway {
        return Ok(v.clone());
    }
    let cut: String = chars[..(length - end_len) as usize].iter().collect();
    let kept = if b.flag(2) {
        cut
    } else {
        cut.rsplit_once(' ')
            .map_or(cut.clone(), |(head, _)| head.to_owned())
    };
    Ok(Value::from(format!("{kept}{end}")))
}

fn unique(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(
        &kwargs,
        "sync_do_unique",
        &args,
        &["value", "case_sensitive", "attribute"],
    )?;
    let parts = attribute_parts(&b.or(2, none()));
    let case_sensitive = b.flag(1);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in items_of(state, b.value())? {
        let mut k = get_path(state, &item, &parts)?;
        if !case_sensitive {
            k = ignore_case(k);
        }
        if seen.insert(HashKey::of(&k)?) {
            out.push(item);
        }
    }
    Ok(PyList::of(out))
}

/// `urllib.parse.quote_from_bytes(text.encode(), safe)`.
fn quote(text: &str, safe: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || safe.as_bytes().contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn url_quote(state: &State, v: &Value, for_qs: bool) -> Result<String, Error> {
    let text = soft(state, v)?;
    let quoted = quote(&text, if for_qs { "" } else { "/" });
    Ok(if for_qs {
        quoted.replace("%20", "+")
    } else {
        quoted
    })
}

fn urlencode(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_urlencode", &args, &["value"])?;
    let v = b.value();
    let pairs = match kind(v) {
        Kind::Str(_) | Kind::None | Kind::Bool(_) | Kind::Int(_) | Kind::Float(_) => {
            return str_value(url_quote(state, v, false)?);
        }
        Kind::Dict(d) => d.entries(),
        _ => items_of(state, v)?
            .into_iter()
            .map(|pair| {
                let parts = iterate(&pair)?;
                match &parts[..] {
                    [k, value] => Ok((k.clone(), value.clone())),
                    _ => Err(py::value_error("too many values to unpack (expected 2)")),
                }
            })
            .collect::<Result<_, Error>>()?,
    };
    let mut out = Vec::with_capacity(pairs.len());
    for (k, value) in pairs {
        out.push(format!(
            "{}={}",
            url_quote(state, &k, true)?,
            url_quote(state, &value, true)?
        ));
    }
    str_value(out.join("&"))
}

fn wordcount(state: &mut State, args: Rest<Value>, kwargs: Kwargs) -> Result<Value, Error> {
    let b = Bound::new(&kwargs, "do_wordcount", &args, &["s"])?;
    let s = soft(state, b.value())?;
    let mut n = 0;
    let mut in_word = false;
    for c in s.chars() {
        let w = c.is_alphanumeric() || c == '_';
        if w && !in_word {
            n += 1;
        }
        in_word = w;
    }
    Ok(int(n))
}

// tests

fn one(args: &[Value]) -> Value {
    args.first().cloned().unwrap_or(Value::UNDEFINED)
}

fn odd(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let r = ops::rem(state, Rest(vec![one(&args), int(2)]))?;
    Ok(py::eq(&r, &int(1)))
}

fn even(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let r = ops::rem(state, Rest(vec![one(&args), int(2)]))?;
    Ok(py::eq(&r, &int(0)))
}

fn divisibleby(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let num = args.get(1).cloned().unwrap_or(Value::UNDEFINED);
    let r = ops::rem(state, Rest(vec![one(&args), num]))?;
    Ok(py::eq(&r, &int(0)))
}

fn defined(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(!py::is_undefined(&one(&args)))
}

fn undefined(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(py::is_undefined(&one(&args)))
}

fn is_filter(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(one(&args)
        .as_str()
        .is_some_and(|n| filters().iter().any(|(name, _)| *name == n)))
}

fn is_test(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(one(&args)
        .as_str()
        .is_some_and(|n| tests().iter().any(|(name, _)| *name == n)))
}

fn is_none(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::None))
}

fn boolean(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::Bool(_)))
}

fn is_false(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::Bool(false)))
}

fn is_true(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::Bool(true)))
}

fn integer(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::Int(_)))
}

fn is_float(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::Float(_)))
}

fn is_lower(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let s = to_str(state, &one(&args))?;
    let mut any = false;
    for c in s.chars() {
        if c.is_uppercase() {
            return Ok(false);
        }
        any |= c.is_lowercase();
    }
    Ok(any)
}

fn is_upper(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let s = to_str(state, &one(&args))?;
    let mut any = false;
    for c in s.chars() {
        if c.is_lowercase() {
            return Ok(false);
        }
        any |= c.is_uppercase();
    }
    Ok(any)
}

fn is_string(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::Str(_)))
}

fn mapping(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(kind(&one(&args)), Kind::Dict(_) | Kind::Map))
}

fn is_number(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(matches!(
        kind(&one(&args)),
        Kind::Bool(_) | Kind::Int(_) | Kind::Float(_)
    ))
}

fn sequence(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let v = one(&args);
    // Undefined has a length and __getitem__; StrictUndefined's length raises, which the test
    // catches
    if py::is_undefined(&v) {
        return Ok(check_strict(state, &v).is_ok());
    }
    Ok(matches!(
        kind(&v),
        Kind::Str(_)
            | Kind::List(_)
            | Kind::Tuple(_)
            | Kind::Dict(_)
            | Kind::Range(_)
            | Kind::Seq
            | Kind::Map
    ))
}

fn iterable(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let v = one(&args);
    check_strict(state, &v)?;
    Ok(match kind(&v) {
        Kind::Undefined
        | Kind::Str(_)
        | Kind::List(_)
        | Kind::Tuple(_)
        | Kind::Dict(_)
        | Kind::View(_)
        | Kind::Range(_)
        | Kind::Seq
        | Kind::Map => true,
        Kind::Other => v.try_iter().is_ok(),
        _ => false,
    })
}

fn callable(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let v = one(&args);
    Ok(match kind(&v) {
        Kind::Method(_) => true,
        Kind::Other => v.kind() == minijinja::value::ValueKind::Plain,
        _ => false,
    })
}

fn sameas(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let other = args.get(1).cloned().unwrap_or(Value::UNDEFINED);
    Ok(py::same_object(&one(&args), &other))
}

fn escaped(_: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    Ok(one(&args).is_safe())
}

fn is_in(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    let seq = args.get(1).cloned().unwrap_or(Value::UNDEFINED);
    contains(state, &one(&args), &seq)
}

fn cmp_test(state: &State, args: &[Value], op: &str) -> Result<bool, Error> {
    let other = args.get(1).cloned().unwrap_or(Value::UNDEFINED);
    compare_op(state, op, &one(args), &other)
}

fn t_eq(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    cmp_test(state, &args, "eq")
}
fn t_ne(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    cmp_test(state, &args, "ne")
}
fn t_gt(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    cmp_test(state, &args, "gt")
}
fn t_ge(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    cmp_test(state, &args, "ge")
}
fn t_lt(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    cmp_test(state, &args, "lt")
}
fn t_le(state: &mut State, args: Rest<Value>, _kwargs: Kwargs) -> Result<bool, Error> {
    cmp_test(state, &args, "le")
}
