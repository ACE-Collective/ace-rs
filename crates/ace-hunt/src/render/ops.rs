//! Python's operators, literals and lookups, which a template's are rewritten into
//! ([`super::rewrite`]): `+` on two lists makes a list, `'a' < 1` is a TypeError, `~` prints with
//! `str()`, `{}` is a mutable dict, and `d.items` is a method before it's a key, as Jinja's sandbox
//! looks them up.
//!
//! An undefined operand follows Jinja's Undefined: arithmetic, ordering and attribute lookup on
//! one fail in both modes; printing, `~`, `==`, `in` and truthiness fail only under
//! StrictUndefined.

use minijinja::value::{Rest, Value};
use minijinja::{Error, ErrorKind, State, UndefinedBehavior};

use super::budget;
use super::py::{
    self, BoundMethod, DictInner, Kind, Num, PyDict, PyList, PyTuple, compare, eq, int, iterate,
    kind, number, str_of, type_error, type_name,
};

pub fn strict(state: &State) -> bool {
    state.undefined_behavior() == UndefinedBehavior::Strict
}

pub fn undefined_error(what: &str) -> Error {
    Error::new(ErrorKind::UndefinedError, format!("{what} is undefined"))
}

/// Fails on an undefined value under StrictUndefined, where Jinja's would raise.
pub fn check_strict(state: &State, v: &Value) -> Result<(), Error> {
    if strict(state) && v.is_undefined() {
        Err(undefined_error("a value"))
    } else {
        Ok(())
    }
}

/// Fails on an undefined value in either mode, as Jinja's Undefined does for arithmetic.
fn check_defined(v: &Value) -> Result<(), Error> {
    if py::is_undefined(v) {
        Err(undefined_error("a value"))
    } else {
        Ok(())
    }
}

/// `str()` of a value, which fails on an undefined one under StrictUndefined.
pub fn to_str(state: &State, v: &Value) -> Result<String, Error> {
    check_strict(state, v)?;
    Ok(str_of(v))
}

fn two(args: &[Value]) -> Result<(&Value, &Value), Error> {
    match args {
        [a, b] => Ok((a, b)),
        _ => Err(Error::new(
            ErrorKind::InvalidOperation,
            "expected two operands",
        )),
    }
}

fn unsupported(op: &str, a: &Value, b: &Value) -> Error {
    type_error(format!(
        "unsupported operand type(s) for {op}: '{}' and '{}'",
        type_name(a),
        type_name(b)
    ))
}

fn overflow() -> Error {
    Error::new(
        ErrorKind::InvalidOperation,
        "OverflowError: integer result past 128 bits (ace-rs limit; Python's ints have none)",
    )
}

fn float(f: f64) -> Value {
    Value::from(f)
}

fn as_f64(n: Num) -> f64 {
    match n {
        Num::Int(i) => i as f64,
        Num::Float(f) => f,
    }
}

fn repeat_count(n: i128) -> usize {
    usize::try_from(n.max(0)).unwrap_or(usize::MAX)
}

pub fn add(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let (a, b) = two(&args)?;
    check_defined(a)?;
    check_defined(b)?;
    let (ka, kb) = (kind(a), kind(b));
    if let (Some(x), Some(y)) = (number(&ka), number(&kb)) {
        return Ok(match (x, y) {
            (Num::Int(x), Num::Int(y)) => int(x.checked_add(y).ok_or_else(overflow)?),
            _ => float(as_f64(x) + as_f64(y)),
        });
    }
    match (ka, kb) {
        (Kind::Str(x), Kind::Str(y)) => {
            budget::string(x.len() + y.len())?;
            Ok(Value::from(format!("{x}{y}")))
        }
        (Kind::List(_) | Kind::Seq, Kind::List(_) | Kind::Seq) => {
            let mut items = iterate(a)?;
            items.extend(iterate(b)?);
            budget::items(items.len())?;
            Ok(PyList::of(items))
        }
        (Kind::Tuple(x), Kind::Tuple(y)) => {
            let mut items = x.0.clone();
            items.extend(y.0.iter().cloned());
            budget::items(items.len())?;
            Ok(PyTuple::of(items))
        }
        _ => Err(if matches!(kind(a), Kind::Str(_)) {
            type_error(format!(
                "can only concatenate str (not \"{}\") to str",
                type_name(b)
            ))
        } else {
            unsupported("+", a, b)
        }),
    }
}

pub fn sub(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let (a, b) = two(&args)?;
    check_defined(a)?;
    check_defined(b)?;
    match (number(&kind(a)), number(&kind(b))) {
        (Some(Num::Int(x)), Some(Num::Int(y))) => Ok(int(x.checked_sub(y).ok_or_else(overflow)?)),
        (Some(x), Some(y)) => Ok(float(as_f64(x) - as_f64(y))),
        _ => Err(unsupported("-", a, b)),
    }
}

pub fn mul(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let (a, b) = two(&args)?;
    check_defined(a)?;
    check_defined(b)?;
    let (ka, kb) = (kind(a), kind(b));
    if let (Some(x), Some(y)) = (number(&ka), number(&kb)) {
        return Ok(match (x, y) {
            (Num::Int(x), Num::Int(y)) => int(x.checked_mul(y).ok_or_else(overflow)?),
            _ => float(as_f64(x) * as_f64(y)),
        });
    }
    let (seq, n) = match (&ka, &kb) {
        (_, Kind::Int(_) | Kind::Bool(_)) => (a, py::as_int(b).unwrap_or(0)),
        (Kind::Int(_) | Kind::Bool(_), _) => (b, py::as_int(a).unwrap_or(0)),
        _ => {
            return Err(type_error(format!(
                "can't multiply sequence by non-int of type '{}'",
                type_name(b)
            )));
        }
    };
    let n = repeat_count(n);
    match kind(seq) {
        Kind::Str(s) => {
            budget::string(s.len().saturating_mul(n))?;
            Ok(Value::from(s.repeat(n)))
        }
        Kind::List(_) | Kind::Seq | Kind::Tuple(_) => {
            let items = iterate(seq)?;
            budget::items(items.len().saturating_mul(n))?;
            let out: Vec<Value> = std::iter::repeat_n(items, n).flatten().collect();
            Ok(if matches!(kind(seq), Kind::Tuple(_)) {
                PyTuple::of(out)
            } else {
                PyList::of(out)
            })
        }
        _ => Err(unsupported("*", a, b)),
    }
}

fn zero_division(what: &str) -> Error {
    Error::new(
        ErrorKind::InvalidOperation,
        format!("ZeroDivisionError: {what}"),
    )
}

pub fn div(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let (a, b) = two(&args)?;
    check_defined(a)?;
    check_defined(b)?;
    match (number(&kind(a)), number(&kind(b))) {
        (Some(x), Some(y)) => {
            let d = as_f64(y);
            if d == 0.0 {
                return Err(zero_division("division by zero"));
            }
            Ok(float(as_f64(x) / d))
        }
        _ => Err(unsupported("/", a, b)),
    }
}

pub fn floordiv(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let (a, b) = two(&args)?;
    check_defined(a)?;
    check_defined(b)?;
    match (number(&kind(a)), number(&kind(b))) {
        (Some(Num::Int(x)), Some(Num::Int(y))) => {
            if y == 0 {
                return Err(zero_division("integer division or modulo by zero"));
            }
            let q = x.checked_div(y).ok_or_else(overflow)?;
            Ok(int(q - i128::from(x % y != 0 && ((x < 0) != (y < 0)))))
        }
        (Some(x), Some(y)) => {
            let (x, y) = (as_f64(x), as_f64(y));
            if y == 0.0 {
                return Err(zero_division("float floor division by zero"));
            }
            Ok(float((x / y).floor()))
        }
        _ => Err(unsupported("//", a, b)),
    }
}

pub fn rem(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let (a, b) = two(&args)?;
    check_defined(a)?;
    check_defined(b)?;
    match (number(&kind(a)), number(&kind(b))) {
        (Some(Num::Int(x)), Some(Num::Int(y))) => {
            if y == 0 {
                return Err(zero_division("integer modulo by zero"));
            }
            let r = x % y;
            Ok(int(if r != 0 && ((r < 0) != (y < 0)) {
                r + y
            } else {
                r
            }))
        }
        (Some(x), Some(y)) => {
            let (x, y) = (as_f64(x), as_f64(y));
            if y == 0.0 {
                return Err(zero_division("float modulo"));
            }
            let r = x % y;
            Ok(float(if r != 0.0 && ((r < 0.0) != (y < 0.0)) {
                r + y
            } else {
                r
            }))
        }
        _ if matches!(kind(a), Kind::Str(_)) => Err(Error::new(
            ErrorKind::InvalidOperation,
            "printf-style string formatting isn't ported (ace-rs); no hunt template uses it",
        )),
        _ => Err(unsupported("%", a, b)),
    }
}

pub fn pow(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let (a, b) = two(&args)?;
    check_defined(a)?;
    check_defined(b)?;
    match (number(&kind(a)), number(&kind(b))) {
        (Some(Num::Int(x)), Some(Num::Int(y))) if y >= 0 => {
            let e = u32::try_from(y).map_err(|_| overflow())?;
            Ok(int(x.checked_pow(e).ok_or_else(overflow)?))
        }
        (Some(x), Some(y)) => {
            let (x, y) = (as_f64(x), as_f64(y));
            if x == 0.0 && y < 0.0 {
                return Err(zero_division("0.0 cannot be raised to a negative power"));
            }
            Ok(float(x.powf(y)))
        }
        _ => Err(unsupported("** or pow()", a, b)),
    }
}

pub fn neg(_: &State, v: Value) -> Result<Value, Error> {
    check_defined(&v)?;
    match number(&kind(&v)) {
        Some(Num::Int(i)) => Ok(int(i.checked_neg().ok_or_else(overflow)?)),
        Some(Num::Float(f)) => Ok(float(-f)),
        None => Err(type_error(format!(
            "bad operand type for unary -: '{}'",
            type_name(&v)
        ))),
    }
}

/// `~`: `str()` of each side joined.
pub fn concat(state: &State, args: Rest<Value>) -> Result<Value, Error> {
    let mut out = String::new();
    for v in args.iter() {
        out.push_str(&to_str(state, v)?);
        budget::string(out.len())?;
    }
    Ok(Value::from(out))
}

pub fn equal(state: &State, a: &Value, b: &Value) -> Result<bool, Error> {
    check_strict(state, a)?;
    check_strict(state, b)?;
    Ok(eq(a, b))
}

/// `in`: a substring of a string, a key of a dict, an item of anything else iterable.
pub fn contains(state: &State, item: &Value, container: &Value) -> Result<bool, Error> {
    check_strict(state, container)?;
    match kind(container) {
        Kind::Undefined => Ok(false),
        Kind::Str(s) => match kind(item) {
            Kind::Str(needle) => Ok(s.contains(needle)),
            _ => Err(type_error(format!(
                "'in <string>' requires string as left operand, not {}",
                type_name(item)
            ))),
        },
        Kind::Dict(d) => {
            check_strict(state, item)?;
            Ok(d.lookup(item)?.is_some())
        }
        Kind::View(view) if view.part == py::ViewPart::Keys => {
            check_strict(state, item)?;
            Ok(view.dict.lookup(item)?.is_some())
        }
        Kind::Range(r) => Ok(match kind(item) {
            Kind::Int(_) | Kind::Bool(_) => {
                let i = py::as_int(item).unwrap_or(0);
                (0..r.len()).any(|n| r.get(n) == i)
            }
            _ => iterate(container)?.iter().any(|x| eq(x, item)),
        }),
        _ => {
            let items = iterate(container)?;
            if !items.is_empty() {
                check_strict(state, item)?;
            }
            Ok(items.iter().any(|x| eq(x, item)))
        }
    }
}

/// A comparison, by its name in [`super::rewrite`].
pub fn compare_op(state: &State, op: &str, a: &Value, b: &Value) -> Result<bool, Error> {
    use std::cmp::Ordering::*;
    let order = |sym: &str| -> Result<Option<std::cmp::Ordering>, Error> { compare(a, b, sym) };
    Ok(match op {
        "eq" => equal(state, a, b)?,
        "ne" => !equal(state, a, b)?,
        "lt" => order("<")? == Some(Less),
        "le" => matches!(order("<=")?, Some(Less | Equal)),
        "gt" => order(">")? == Some(Greater),
        "ge" => matches!(order(">=")?, Some(Greater | Equal)),
        "in" => contains(state, a, b)?,
        "notin" => !contains(state, a, b)?,
        other => {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                format!("no comparison {other}"),
            ));
        }
    })
}

/// `a < b < c`, as `%compare(a, 'lt', b, 'lt', c)`: each pair in turn, stopping at the first
/// that's false, as Python does.
pub fn compare_chain(state: &State, args: Rest<Value>) -> Result<Value, Error> {
    let mut left = args.first().cloned().unwrap_or_default();
    for pair in args[1..].chunks(2) {
        let [op, right] = pair else {
            return Err(Error::new(ErrorKind::InvalidOperation, "bad comparison"));
        };
        if !compare_op(state, op.as_str().unwrap_or(""), &left, right)? {
            return Ok(Value::from(false));
        }
        left = right.clone();
    }
    Ok(Value::from(true))
}

/// What a `for` loops over: anything Python iterates, or a TypeError.
pub fn iter_check(_: &State, v: Value) -> Result<Value, Error> {
    match kind(&v) {
        Kind::None | Kind::Bool(_) | Kind::Int(_) | Kind::Float(_) | Kind::Method(_) => Err(
            type_error(format!("'{}' object is not iterable", type_name(&v))),
        ),
        _ => Ok(v),
    }
}

pub fn list(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    Ok(PyList::of(args.0))
}

pub fn tuple(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    Ok(PyTuple::of(args.0))
}

pub fn dict(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let mut inner = DictInner::default();
    for pair in args.chunks(2) {
        if let [k, v] = pair {
            inner.insert(k.clone(), v.clone())?;
        }
    }
    Ok(PyDict::of(inner))
}

const DICT_METHODS: &[&str] = &[
    "clear",
    "copy",
    "fromkeys",
    "get",
    "items",
    "keys",
    "pop",
    "popitem",
    "setdefault",
    "update",
    "values",
];
const LIST_METHODS: &[&str] = &[
    "append", "clear", "copy", "count", "extend", "index", "insert", "pop", "remove", "reverse",
    "sort",
];
const TUPLE_METHODS: &[&str] = &["count", "index"];
const STR_METHODS: &[&str] = &[
    "capitalize",
    "casefold",
    "center",
    "count",
    "encode",
    "endswith",
    "expandtabs",
    "find",
    "format",
    "format_map",
    "index",
    "isalnum",
    "isalpha",
    "isascii",
    "isdecimal",
    "isdigit",
    "isidentifier",
    "islower",
    "isnumeric",
    "isprintable",
    "isspace",
    "istitle",
    "isupper",
    "join",
    "ljust",
    "lower",
    "lstrip",
    "maketrans",
    "partition",
    "removeprefix",
    "removesuffix",
    "replace",
    "rfind",
    "rindex",
    "rjust",
    "rpartition",
    "rsplit",
    "rstrip",
    "split",
    "splitlines",
    "startswith",
    "strip",
    "swapcase",
    "title",
    "translate",
    "upper",
    "zfill",
];

/// Python's `getattr(obj, name)` for the attributes a value has: its type's methods.
pub fn python_attr(v: &Value, name: &str) -> Option<Value> {
    let methods: &[&str] = match kind(v) {
        Kind::Dict(_) => DICT_METHODS,
        Kind::List(_) => LIST_METHODS,
        Kind::Tuple(_) => TUPLE_METHODS,
        Kind::Str(_) => STR_METHODS,
        _ => return None,
    };
    // the sandbox refuses an attribute starting with `_`, and none of these does
    methods.contains(&name).then(|| {
        Value::from_object(BoundMethod {
            receiver: v.clone(),
            name: name.to_owned(),
        })
    })
}

/// `obj.name`: Jinja's sandboxed getattr, an attribute first and then an item.
pub fn getattr(state: &State, obj: Value, name: Value) -> Result<Value, Error> {
    let name = name.as_str().unwrap_or("");
    if py::is_undefined(&obj) {
        return Err(undefined_error(&format!(
            "attribute {name} of an undefined value"
        )));
    }
    if let Some(method) = python_attr(&obj, name) {
        return Ok(method);
    }
    if name.starts_with("__") && name.ends_with("__") && strict(state) {
        // every Python object has dunder attributes, which the sandbox answers with an
        // Undefined that raises SecurityError, not UndefinedError, when StrictUndefined prints it
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            format!(
                "SecurityError: access to attribute '{name}' of '{}' object is unsafe.",
                type_name(&obj)
            ),
        ));
    }
    item_or_undefined(&obj, &Value::from(name))
}

/// `obj[key]`: Jinja's sandboxed getitem, an item first and then, for a string, an attribute.
pub fn getitem(_: &State, obj: Value, key: Value) -> Result<Value, Error> {
    if py::is_undefined(&obj) {
        // Undefined's __getitem__ raises
        return Err(undefined_error("an item of an undefined value"));
    }
    let found = item_or_undefined(&obj, &key)?;
    if !found.is_undefined() {
        return Ok(found);
    }
    if let Some(name) = key.as_str()
        && let Some(method) = python_attr(&obj, name)
    {
        return Ok(method);
    }
    Ok(found)
}

fn item_or_undefined(obj: &Value, key: &Value) -> Result<Value, Error> {
    Ok(match kind(obj) {
        Kind::Dict(d) => d.lookup(key).ok().flatten().unwrap_or(Value::UNDEFINED),
        Kind::List(_) | Kind::Tuple(_) | Kind::Range(_) | Kind::Str(_) | Kind::Seq => {
            match py::as_int(key) {
                Some(i) => {
                    let items = iterate(obj)?;
                    py::index(i, items.len())
                        .map(|i| items[i].clone())
                        .unwrap_or(Value::UNDEFINED)
                }
                None => Value::UNDEFINED,
            }
        }
        Kind::None
        | Kind::Bool(_)
        | Kind::Int(_)
        | Kind::Float(_)
        | Kind::View(_)
        | Kind::Method(_)
        | Kind::Undefined => Value::UNDEFINED,
        Kind::Map | Kind::Other => match key.as_str() {
            Some(name) => obj.get_attr(name).unwrap_or(Value::UNDEFINED),
            None => obj.get_item(key).unwrap_or(Value::UNDEFINED),
        },
    })
}

/// `obj[start:stop:step]`, as Python slices; anything that can't be sliced gives an undefined
/// value, as Jinja's getitem does when the subscript raises.
pub fn slice(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    // Jinja2 compiles a slice to Python's own subscript, not its getitem, so what it raises
    // isn't caught
    let [obj, start, stop, step] = &args[..] else {
        return Err(type_error("bad slice"));
    };
    if py::is_undefined(obj) {
        return Err(undefined_error("a slice of an undefined value"));
    }
    let bound = |v: &Value| -> Result<Option<i128>, Error> {
        match kind(v) {
            Kind::None => Ok(None),
            Kind::Int(i) => Ok(Some(i)),
            Kind::Bool(b) => Ok(Some(i128::from(b))),
            _ => Err(type_error(
                "slice indices must be integers or None or have an __index__ method",
            )),
        }
    };
    let (start, stop, step) = (bound(start)?, bound(stop)?, bound(step)?);
    let step = step.unwrap_or(1);
    if step == 0 {
        return Err(py::value_error("slice step cannot be zero"));
    }
    let picked = |len: usize| -> Vec<usize> { slice_indices(len, start, stop, step) };
    Ok(match kind(obj) {
        Kind::Str(s) => {
            let chars: Vec<char> = s.chars().collect();
            Value::from(
                picked(chars.len())
                    .into_iter()
                    .map(|i| chars[i])
                    .collect::<String>(),
            )
        }
        Kind::List(_) | Kind::Seq | Kind::Tuple(_) | Kind::Range(_) => {
            let items = iterate(obj)?;
            let out: Vec<Value> = picked(items.len())
                .into_iter()
                .map(|i| items[i].clone())
                .collect();
            match kind(obj) {
                Kind::Tuple(_) => PyTuple::of(out),
                // a range's slice is a range in Python; as a list it iterates the same
                _ => PyList::of(out),
            }
        }
        _ => {
            return Err(type_error(format!(
                "'{}' object is not subscriptable",
                type_name(obj)
            )));
        }
    })
}

/// CPython's PySlice_AdjustIndices, as the indices it picks.
pub fn slice_indices(
    len: usize,
    start: Option<i128>,
    stop: Option<i128>,
    step: i128,
) -> Vec<usize> {
    let len = len as i128;
    let adjust = |v: Option<i128>, default: i128, low: i128, high: i128| -> i128 {
        match v {
            None => default,
            Some(mut v) => {
                if v < 0 {
                    v += len;
                    if v < 0 {
                        v = low;
                    }
                } else if v >= high {
                    v = high;
                }
                v
            }
        }
    };
    let mut out = Vec::new();
    if step > 0 {
        let start = adjust(start, 0, 0, len);
        let stop = adjust(stop, len, 0, len);
        let mut i = start;
        while i < stop {
            out.push(i as usize);
            i += step;
        }
    } else {
        let start = adjust(start, len - 1, -1, len - 1);
        let stop = adjust(stop, -1, -1, len - 1);
        let mut i = start;
        while i > stop {
            out.push(i as usize);
            i += step;
        }
    }
    out
}

/// `range()`, which Jinja's sandbox caps at 100,000 items.
pub fn range(_: &State, args: Rest<Value>) -> Result<Value, Error> {
    let ints: Vec<i128> = args
        .iter()
        .map(|v| {
            py::as_int(v).ok_or_else(|| {
                type_error(format!(
                    "'{}' object cannot be interpreted as an integer",
                    type_name(v)
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    let (start, stop, step) = match ints[..] {
        [stop] => (0, stop, 1),
        [start, stop] => (start, stop, 1),
        [start, stop, step] => (start, stop, step),
        _ => {
            return Err(type_error(format!(
                "range expected at most 3 arguments, got {}",
                ints.len()
            )));
        }
    };
    if step == 0 {
        return Err(py::value_error("range() arg 3 must not be zero"));
    }
    let r = py::PyRange { start, stop, step };
    if r.len() > 100_000 {
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            "OverflowError: Range too big. The sandbox blocks ranges larger than MAX_RANGE (100000).",
        ));
    }
    Ok(Value::from_object(r))
}

/// `dict(...)`: a dict of keyword arguments, or of another dict or pairs and then keywords.
pub fn dict_global(
    state: &State,
    args: Rest<Value>,
    kwargs: minijinja::value::Kwargs,
) -> Result<Value, Error> {
    let mut inner = DictInner::default();
    let positional: Vec<Value> = args.0;
    let keys: Vec<String> = kwargs.args().map(str::to_owned).collect();
    for name in keys {
        let v: Value = kwargs.get(&name)?;
        inner.insert(Value::from(name), v)?;
    }
    let mut out = DictInner::default();
    match positional.as_slice() {
        [] => {}
        [source] => super::methods::update_from(state, &mut out, source)?,
        _ => {
            return Err(type_error(format!(
                "dict expected at most 1 argument, got {}",
                positional.len()
            )));
        }
    }
    for (k, v) in inner.entries() {
        out.insert(k.clone(), v.clone())?;
    }
    Ok(PyDict::of(out))
}
