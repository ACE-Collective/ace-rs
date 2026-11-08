//! Python's values inside a template: what a hunt's Jinja sees in ace3.
//!
//! ace3 renders against Python objects, so a list is mutable (`{% set _ = seen.append(x) %}`), a
//! dict keeps its insertion order and finds `1` and `1.0` as one key, and printing a value is
//! `str()` (`True`, `None`, `['a', 1]`). minijinja's own sequences and maps are immutable and print
//! as JSON, so lists, tuples and dicts are the objects here, and [`kind`] tells every value apart as
//! Python would. Equality, ordering and hashing are Python's ([`eq`], [`compare`], [`HashKey`]).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use minijinja::value::{Enumerator, Kwargs, Object, ObjectRepr, Value as JValue, ValueKind};
use minijinja::{Error, ErrorKind};

use crate::value::Value as Loaded;

/// A Python list: shared and mutable, as a template's `append` needs.
#[derive(Debug, Default)]
pub struct PyList(Mutex<Vec<JValue>>);

/// A Python tuple.
#[derive(Debug, Default)]
pub struct PyTuple(pub Vec<JValue>);

/// A Python dict: insertion order, with keys found by Python's hash equality.
#[derive(Debug, Default)]
pub struct PyDict(Mutex<DictInner>);

#[derive(Debug, Default, Clone)]
pub struct DictInner {
    entries: Vec<(JValue, JValue)>,
    index: HashMap<HashKey, usize>,
}

/// `dict.keys()`, `.values()` and `.items()`: live views of a dict.
#[derive(Debug)]
pub struct DictView {
    pub dict: Arc<PyDict>,
    pub part: ViewPart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewPart {
    Keys,
    Values,
    Items,
}

/// Python's `range`, which the sandbox caps at 100,000 items.
#[derive(Debug)]
pub struct PyRange {
    pub start: i128,
    pub stop: i128,
    pub step: i128,
}

/// A method looked up but not called, such as `{{ d.items }}`: what Python prints for it.
#[derive(Debug)]
pub struct BoundMethod {
    pub receiver: JValue,
    pub name: String,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // a panic while a template held the lock leaves the data as it was; nothing is half-written
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl PyList {
    pub fn of(items: Vec<JValue>) -> JValue {
        JValue::from_object(PyList(Mutex::new(items)))
    }

    pub fn items(&self) -> Vec<JValue> {
        lock(&self.0).clone()
    }

    pub fn len(&self) -> usize {
        lock(&self.0).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, i: usize) -> Option<JValue> {
        lock(&self.0).get(i).cloned()
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Vec<JValue>) -> R) -> R {
        f(&mut lock(&self.0))
    }
}

impl PyTuple {
    pub fn of(items: Vec<JValue>) -> JValue {
        JValue::from_object(PyTuple(items))
    }
}

impl DictInner {
    pub fn get(&self, key: &HashKey) -> Option<&JValue> {
        self.index.get(key).map(|&i| &self.entries[i].1)
    }

    /// Sets `key`, keeping the position of an equal key already there, as a dict does.
    pub fn insert(&mut self, key: JValue, value: JValue) -> Result<(), Error> {
        let hash = HashKey::of(&key)?;
        match self.index.get(&hash) {
            Some(&i) => self.entries[i].1 = value,
            None => {
                self.index.insert(hash, self.entries.len());
                self.entries.push((key, value));
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, key: &HashKey) -> Option<JValue> {
        let i = self.index.remove(key)?;
        let (_, value) = self.entries.remove(i);
        for slot in self.index.values_mut() {
            if *slot > i {
                *slot -= 1;
            }
        }
        Some(value)
    }

    pub fn entries(&self) -> &[(JValue, JValue)] {
        &self.entries
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
    }
}

impl PyDict {
    pub fn of(inner: DictInner) -> JValue {
        JValue::from_object(PyDict(Mutex::new(inner)))
    }

    pub fn from_pairs(pairs: Vec<(JValue, JValue)>) -> Result<JValue, Error> {
        let mut inner = DictInner::default();
        for (k, v) in pairs {
            inner.insert(k, v)?;
        }
        Ok(PyDict::of(inner))
    }

    pub fn snapshot(&self) -> DictInner {
        lock(&self.0).clone()
    }

    pub fn entries(&self) -> Vec<(JValue, JValue)> {
        lock(&self.0).entries.clone()
    }

    pub fn len(&self) -> usize {
        lock(&self.0).entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, key: &JValue) -> Result<Option<JValue>, Error> {
        let hash = HashKey::of(key)?;
        Ok(lock(&self.0).get(&hash).cloned())
    }

    pub fn get_str(&self, key: &str) -> Option<JValue> {
        lock(&self.0).get(&HashKey::Str(key.to_owned())).cloned()
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut DictInner) -> R) -> R {
        f(&mut lock(&self.0))
    }
}

impl PyRange {
    pub fn len(&self) -> usize {
        let n = if self.step > 0 && self.start < self.stop {
            (self.stop - self.start - 1) / self.step + 1
        } else if self.step < 0 && self.start > self.stop {
            (self.start - self.stop - 1) / (-self.step) + 1
        } else {
            0
        };
        usize::try_from(n).unwrap_or(usize::MAX)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, i: usize) -> i128 {
        self.start + self.step * i as i128
    }
}

/// Iterates a list by index, so items appended while a loop runs over it are reached, as in
/// Python.
struct LiveList {
    list: Arc<PyList>,
    next: usize,
}

impl Iterator for LiveList {
    type Item = JValue;
    fn next(&mut self) -> Option<JValue> {
        let item = self.list.get(self.next)?;
        self.next += 1;
        Some(item)
    }
    // exact at the time it's asked, which is when a loop starts and takes its length
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.list.len().saturating_sub(self.next);
        (left, Some(left))
    }
}

/// A Python index: negative from the end, and an error past either end.
pub fn index(i: i128, len: usize) -> Option<usize> {
    let len = len as i128;
    let i = if i < 0 { i + len } else { i };
    (0..len).contains(&i).then_some(i as usize)
}

impl Object for PyList {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Seq
    }
    fn get_value(self: &Arc<Self>, key: &JValue) -> Option<JValue> {
        let i = as_int(key)?;
        let items = lock(&self.0);
        index(i, items.len()).map(|i| items[i].clone())
    }
    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Iter(Box::new(LiveList {
            list: self.clone(),
            next: 0,
        }))
    }
    fn enumerator_len(self: &Arc<Self>) -> Option<usize> {
        Some(self.len())
    }
    fn is_true(self: &Arc<Self>) -> bool {
        !PyList::is_empty(self)
    }
    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&repr(&JValue::from_dyn_object(self.clone())))
    }
}

impl Object for PyTuple {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Seq
    }
    fn get_value(self: &Arc<Self>, key: &JValue) -> Option<JValue> {
        let i = as_int(key)?;
        index(i, self.0.len()).map(|i| self.0[i].clone())
    }
    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Values(self.0.clone())
    }
    fn enumerator_len(self: &Arc<Self>) -> Option<usize> {
        Some(self.0.len())
    }
    fn is_true(self: &Arc<Self>) -> bool {
        !self.0.is_empty()
    }
    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&repr(&JValue::from_dyn_object(self.clone())))
    }
}

impl Object for PyDict {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Map
    }
    fn get_value(self: &Arc<Self>, key: &JValue) -> Option<JValue> {
        self.lookup(key).ok().flatten()
    }
    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Values(self.entries().into_iter().map(|(k, _)| k).collect())
    }
    fn enumerator_len(self: &Arc<Self>) -> Option<usize> {
        Some(self.len())
    }
    fn is_true(self: &Arc<Self>) -> bool {
        !PyDict::is_empty(self)
    }
    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&repr(&JValue::from_dyn_object(self.clone())))
    }
}

impl DictView {
    pub fn items(&self) -> Vec<JValue> {
        self.dict
            .entries()
            .into_iter()
            .map(|(k, v)| match self.part {
                ViewPart::Keys => k,
                ViewPart::Values => v,
                ViewPart::Items => PyTuple::of(vec![k, v]),
            })
            .collect()
    }
}

impl Object for DictView {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Iterable
    }
    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Values(self.items())
    }
    fn enumerator_len(self: &Arc<Self>) -> Option<usize> {
        Some(self.dict.len())
    }
    fn is_true(self: &Arc<Self>) -> bool {
        !self.dict.is_empty()
    }
    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&repr(&JValue::from_dyn_object(self.clone())))
    }
}

impl Object for PyRange {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Seq
    }
    fn get_value(self: &Arc<Self>, key: &JValue) -> Option<JValue> {
        let i = as_int(key)?;
        index(i, PyRange::len(self)).map(|i| JValue::from(self.get(i)))
    }
    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Seq(PyRange::len(self))
    }
    fn enumerator_len(self: &Arc<Self>) -> Option<usize> {
        Some(PyRange::len(self))
    }
    fn is_true(self: &Arc<Self>) -> bool {
        !PyRange::is_empty(self)
    }
    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&repr(&JValue::from_dyn_object(self.clone())))
    }
}

impl Object for BoundMethod {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Plain
    }
    fn call(
        self: &Arc<Self>,
        state: &mut minijinja::State<'_, '_>,
        args: &[JValue],
    ) -> Result<JValue, Error> {
        super::methods::call_method(state, &self.receiver, &self.name, args)
    }
    fn render(self: &Arc<Self>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&repr(&JValue::from_dyn_object(self.clone())))
    }
}

/// The Undefined Jinja2 gives for an inline if without an else: its plain one, which prints as
/// nothing even under StrictUndefined.
#[derive(Debug)]
pub struct LenientUndefined;

impl Object for LenientUndefined {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Iterable
    }
    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Empty
    }
    fn is_true(self: &Arc<Self>) -> bool {
        false
    }
    fn render(self: &Arc<Self>, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

/// Undefined, StrictUndefined or the lenient one.
pub fn is_undefined(v: &JValue) -> bool {
    matches!(kind(v), Kind::Undefined)
}

/// A value as Python tells it apart.
pub enum Kind<'a> {
    Undefined,
    None,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(&'a str),
    List(Arc<PyList>),
    Tuple(Arc<PyTuple>),
    Dict(Arc<PyDict>),
    View(Arc<DictView>),
    Range(Arc<PyRange>),
    Method(Arc<BoundMethod>),
    /// minijinja's own sequence or map, which nothing here makes; treated as a list or a dict.
    Seq,
    Map,
    /// Anything else: a macro, `loop`, a namespace, a function.
    Other,
}

pub fn as_int(v: &JValue) -> Option<i128> {
    match kind(v) {
        Kind::Int(i) => Some(i),
        Kind::Bool(b) => Some(i128::from(b)),
        _ => None,
    }
}

pub fn kind(v: &JValue) -> Kind<'_> {
    match v.kind() {
        ValueKind::Undefined => Kind::Undefined,
        ValueKind::None => Kind::None,
        ValueKind::Bool => Kind::Bool(v.is_true()),
        ValueKind::Number => {
            if v.is_integer() {
                match i128::try_from(v.clone()) {
                    Ok(i) => Kind::Int(i),
                    Err(_) => Kind::Float(f64::try_from(v.clone()).unwrap_or(f64::NAN)),
                }
            } else {
                Kind::Float(f64::try_from(v.clone()).unwrap_or(f64::NAN))
            }
        }
        ValueKind::String => Kind::Str(v.as_str().unwrap_or("")),
        _ => {
            if v.downcast_object_ref::<LenientUndefined>().is_some() {
                Kind::Undefined
            } else if let Some(o) = v.downcast_object::<PyList>() {
                Kind::List(o)
            } else if let Some(o) = v.downcast_object::<PyDict>() {
                Kind::Dict(o)
            } else if let Some(o) = v.downcast_object::<PyTuple>() {
                Kind::Tuple(o)
            } else if let Some(o) = v.downcast_object::<DictView>() {
                Kind::View(o)
            } else if let Some(o) = v.downcast_object::<PyRange>() {
                Kind::Range(o)
            } else if let Some(o) = v.downcast_object::<BoundMethod>() {
                Kind::Method(o)
            } else if v.kind() == ValueKind::Seq {
                Kind::Seq
            } else if v.kind() == ValueKind::Map && v.downcast_object_ref::<Kwargs>().is_none() {
                Kind::Map
            } else {
                Kind::Other
            }
        }
    }
}

/// Python's type name, for error messages.
pub fn type_name(v: &JValue) -> &'static str {
    match kind(v) {
        Kind::Undefined => "Undefined",
        Kind::None => "NoneType",
        Kind::Bool(_) => "bool",
        Kind::Int(_) => "int",
        Kind::Float(_) => "float",
        Kind::Str(_) => "str",
        Kind::List(_) | Kind::Seq => "list",
        Kind::Tuple(_) => "tuple",
        Kind::Dict(_) | Kind::Map => "dict",
        Kind::View(v) => match v.part {
            ViewPart::Keys => "dict_keys",
            ViewPart::Values => "dict_values",
            ViewPart::Items => "dict_items",
        },
        Kind::Range(_) => "range",
        Kind::Method(_) => "builtin_function_or_method",
        Kind::Other => "object",
    }
}

/// The items of anything Python iterates, or a TypeError. An undefined value iterates as empty;
/// the caller decides first whether that's allowed.
pub fn iterate(v: &JValue) -> Result<Vec<JValue>, Error> {
    Ok(match kind(v) {
        Kind::Undefined => Vec::new(),
        Kind::Str(s) => s.chars().map(|c| JValue::from(c.to_string())).collect(),
        Kind::List(l) => l.items(),
        Kind::Tuple(t) => t.0.clone(),
        Kind::Dict(d) => d.entries().into_iter().map(|(k, _)| k).collect(),
        Kind::View(view) => view.items(),
        Kind::Range(r) => (0..r.len()).map(|i| JValue::from(r.get(i))).collect(),
        Kind::Seq | Kind::Map | Kind::Other => match v.try_iter() {
            Ok(it) => it.collect(),
            Err(_) => {
                return Err(type_error(format!(
                    "'{}' object is not iterable",
                    type_name(v)
                )));
            }
        },
        _ => {
            return Err(type_error(format!(
                "'{}' object is not iterable",
                type_name(v)
            )));
        }
    })
}

pub fn type_error(message: impl Into<String>) -> Error {
    Error::new(
        ErrorKind::InvalidOperation,
        format!("TypeError: {}", message.into()),
    )
}

pub fn value_error(message: impl Into<String>) -> Error {
    Error::new(
        ErrorKind::InvalidOperation,
        format!("ValueError: {}", message.into()),
    )
}

/// What a Python key hashes as: `1`, `1.0` and `True` are one key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashKey {
    None,
    Int(i128),
    Float(u64),
    Str(String),
    Tuple(Vec<HashKey>),
    Range(i128, i128, i128),
}

impl HashKey {
    pub fn of(v: &JValue) -> Result<HashKey, Error> {
        Ok(match kind(v) {
            Kind::None => HashKey::None,
            Kind::Bool(b) => HashKey::Int(i128::from(b)),
            Kind::Int(i) => HashKey::Int(i),
            Kind::Float(f) => {
                if f.fract() == 0.0 && f.abs() < 1e38 {
                    HashKey::Int(f as i128)
                } else {
                    // every NaN is its own key in Python; one key for them all is close enough
                    HashKey::Float(if f == 0.0 { 0 } else { f.to_bits() })
                }
            }
            Kind::Str(s) => HashKey::Str(s.to_owned()),
            Kind::Tuple(t) => {
                HashKey::Tuple(t.0.iter().map(HashKey::of).collect::<Result<_, _>>()?)
            }
            Kind::Range(r) => HashKey::Range(r.start, r.stop, r.step),
            Kind::Undefined => HashKey::Str("\0undefined".to_owned()),
            _ => return Err(type_error(format!("unhashable type: '{}'", type_name(v)))),
        })
    }
}

/// Python's `==`. An undefined value equals only another, as Jinja's Undefined does; whether
/// comparing one is allowed at all is the caller's question.
pub fn eq(a: &JValue, b: &JValue) -> bool {
    match (kind(a), kind(b)) {
        (Kind::Undefined, Kind::Undefined) => true,
        (Kind::Undefined, _) | (_, Kind::Undefined) => false,
        (Kind::None, Kind::None) => true,
        (Kind::Str(x), Kind::Str(y)) => x == y,
        (Kind::List(_) | Kind::Seq, Kind::List(_) | Kind::Seq) => seq_eq(a, b),
        (Kind::Tuple(x), Kind::Tuple(y)) => {
            x.0.len() == y.0.len() && x.0.iter().zip(&y.0).all(|(p, q)| eq(p, q))
        }
        (Kind::Range(x), Kind::Range(y)) => {
            let (n, m) = (x.len(), y.len());
            n == m && (n == 0 || (x.start == y.start && (n == 1 || x.step == y.step)))
        }
        (Kind::Dict(_) | Kind::Map, Kind::Dict(_) | Kind::Map) => dict_eq(a, b),
        (Kind::View(x), Kind::View(y)) if x.part == ViewPart::Keys && y.part == ViewPart::Keys => {
            dict_keys_eq(&x.dict, &y.dict)
        }
        (Kind::Method(x), Kind::Method(y)) => {
            x.name == y.name && same_object(&x.receiver, &y.receiver)
        }
        (Kind::Other, Kind::Other) => a == b,
        (x, y) => match (number(&x), number(&y)) {
            (Some(p), Some(q)) => num_eq(p, q),
            _ => false,
        },
    }
}

/// Python's `is` for the values a template can make: the same object, or the same singleton.
pub fn same_object(a: &JValue, b: &JValue) -> bool {
    match (kind(a), kind(b)) {
        (Kind::None, Kind::None) => true,
        (Kind::Bool(x), Kind::Bool(y)) => x == y,
        (Kind::List(x), Kind::List(y)) => Arc::ptr_eq(&x, &y),
        (Kind::Dict(x), Kind::Dict(y)) => Arc::ptr_eq(&x, &y),
        (Kind::Tuple(x), Kind::Tuple(y)) => Arc::ptr_eq(&x, &y),
        (Kind::Range(x), Kind::Range(y)) => Arc::ptr_eq(&x, &y),
        _ => false,
    }
}

fn seq_eq(a: &JValue, b: &JValue) -> bool {
    match (iterate(a), iterate(b)) {
        (Ok(x), Ok(y)) => x.len() == y.len() && x.iter().zip(&y).all(|(p, q)| eq(p, q)),
        _ => false,
    }
}

fn pairs(v: &JValue) -> Vec<(JValue, JValue)> {
    match kind(v) {
        Kind::Dict(d) => d.entries(),
        _ => v
            .try_iter()
            .map(|keys| {
                keys.map(|k| {
                    let value = v.get_item(&k).unwrap_or_default();
                    (k, value)
                })
                .collect()
            })
            .unwrap_or_default(),
    }
}

fn dict_eq(a: &JValue, b: &JValue) -> bool {
    let (x, y) = (pairs(a), pairs(b));
    x.len() == y.len()
        && x.iter().all(|(k, v)| {
            y.iter()
                .find(|(l, _)| HashKey::of(k).ok() == HashKey::of(l).ok())
                .is_some_and(|(_, w)| eq(v, w))
        })
}

fn dict_keys_eq(a: &PyDict, b: &PyDict) -> bool {
    let (x, y) = (a.snapshot(), b.snapshot());
    x.entries.len() == y.entries.len() && x.index.keys().all(|k| y.index.contains_key(k))
}

#[derive(Clone, Copy)]
pub enum Num {
    Int(i128),
    Float(f64),
}

pub fn number(k: &Kind<'_>) -> Option<Num> {
    match k {
        Kind::Bool(b) => Some(Num::Int(i128::from(*b))),
        Kind::Int(i) => Some(Num::Int(*i)),
        Kind::Float(f) => Some(Num::Float(*f)),
        _ => None,
    }
}

fn num_eq(a: Num, b: Num) -> bool {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => x == y,
        (Num::Int(x), Num::Float(y)) | (Num::Float(y), Num::Int(x)) => (x as f64) == y,
        (Num::Float(x), Num::Float(y)) => x == y,
    }
}

fn num_cmp(a: Num, b: Num) -> Option<Ordering> {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => Some(x.cmp(&y)),
        (Num::Int(x), Num::Float(y)) => (x as f64).partial_cmp(&y),
        (Num::Float(x), Num::Int(y)) => x.partial_cmp(&(y as f64)),
        (Num::Float(x), Num::Float(y)) => x.partial_cmp(&y),
    }
}

/// Python's `<` and friends: numbers with numbers, strings with strings, a list or tuple with one
/// of its own type item by item, and a TypeError for the rest. `None` means unordered (a NaN).
pub fn compare(a: &JValue, b: &JValue, op: &str) -> Result<Option<Ordering>, Error> {
    let (ka, kb) = (kind(a), kind(b));
    if matches!(ka, Kind::Undefined) || matches!(kb, Kind::Undefined) {
        // Undefined's __lt__ and the rest raise
        return Err(Error::new(
            ErrorKind::UndefinedError,
            "an undefined value is compared",
        ));
    }
    if let (Some(x), Some(y)) = (number(&ka), number(&kb)) {
        return Ok(num_cmp(x, y));
    }
    match (&ka, &kb) {
        (Kind::Str(x), Kind::Str(y)) => return Ok(Some(x.cmp(y))),
        (Kind::List(_) | Kind::Seq, Kind::List(_) | Kind::Seq)
        | (Kind::Tuple(_), Kind::Tuple(_)) => {
            let (x, y) = (iterate(a)?, iterate(b)?);
            for (p, q) in x.iter().zip(&y) {
                if !eq(p, q) {
                    return compare(p, q, op);
                }
            }
            return Ok(Some(x.len().cmp(&y.len())));
        }
        _ => {}
    }
    Err(type_error(format!(
        "'{op}' not supported between instances of '{}' and '{}'",
        type_name(a),
        type_name(b)
    )))
}

/// Python's `str()`. An undefined value is `""`; whether printing one is allowed is the
/// caller's question.
pub fn str_of(v: &JValue) -> String {
    match kind(v) {
        Kind::Undefined => String::new(),
        Kind::Str(s) => s.to_owned(),
        _ => repr(v),
    }
}

/// Python's `repr()`.
pub fn repr(v: &JValue) -> String {
    let mut out = String::new();
    write_repr(v, &mut out, 0);
    out
}

fn write_repr(v: &JValue, out: &mut String, depth: usize) {
    // Python prints a list that holds itself as [...]; a depth bound stands in for that check
    if depth > 64 {
        out.push_str("...");
        return;
    }
    let items = |out: &mut String, items: &[JValue]| {
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            write_repr(item, out, depth + 1);
        }
    };
    match kind(v) {
        Kind::Undefined => out.push_str("Undefined"),
        Kind::None => out.push_str("None"),
        Kind::Bool(b) => out.push_str(if b { "True" } else { "False" }),
        Kind::Int(i) => out.push_str(&i.to_string()),
        Kind::Float(f) => out.push_str(&float_repr(f)),
        Kind::Str(s) => out.push_str(&crate::value::py_repr(s)),
        Kind::List(l) => {
            out.push('[');
            items(out, &l.items());
            out.push(']');
        }
        Kind::Seq => {
            out.push('[');
            items(out, &iterate(v).unwrap_or_default());
            out.push(']');
        }
        Kind::Tuple(t) => {
            out.push('(');
            items(out, &t.0);
            if t.0.len() == 1 {
                out.push(',');
            }
            out.push(')');
        }
        Kind::Map => {
            // the one map minijinja makes here is a namespace
            out.push_str("<Namespace {");
            for (i, (k, value)) in pairs(v).iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_repr(k, out, depth + 1);
                out.push_str(": ");
                write_repr(value, out, depth + 1);
            }
            out.push_str("}>");
        }
        Kind::Dict(_) => {
            out.push('{');
            for (i, (k, value)) in pairs(v).iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_repr(k, out, depth + 1);
                out.push_str(": ");
                write_repr(value, out, depth + 1);
            }
            out.push('}');
        }
        Kind::View(view) => {
            out.push_str(type_name(v));
            out.push_str("([");
            items(out, &view.items());
            out.push_str("])");
        }
        Kind::Range(r) => {
            if r.step == 1 {
                out.push_str(&format!("range({}, {})", r.start, r.stop));
            } else {
                out.push_str(&format!("range({}, {}, {})", r.start, r.stop, r.step));
            }
        }
        Kind::Method(m) => {
            out.push_str(&format!(
                "<built-in method {} of {} object>",
                m.name,
                type_name(&m.receiver)
            ));
        }
        Kind::Other => out.push_str(&v.to_string()),
    }
}

/// Python's `repr()` of a float: the shortest digits that round-trip, in positional notation
/// when the exponent is from -4 to 15 and in scientific notation otherwise.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_owned();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    // Rust's `{:e}` gives the shortest round-trip digits, as Python's repr does
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if f < 0.0 { "-" } else { "" };
    if (-4..16).contains(&exp) {
        let point = exp + 1;
        let body = if point <= 0 {
            format!("0.{}{digits}", "0".repeat((-point) as usize))
        } else if point as usize >= digits.len() {
            format!("{digits}{}.0", "0".repeat(point as usize - digits.len()))
        } else {
            format!(
                "{}.{}",
                &digits[..point as usize],
                &digits[point as usize..]
            )
        };
        format!("{sign}{body}")
    } else {
        let mantissa = if digits.len() == 1 {
            digits
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{mantissa}e{esign}{:02}", exp.abs())
    }
}

/// A loaded or parsed value as the template sees it.
pub fn to_template(v: &Loaded) -> JValue {
    match v {
        Loaded::Null => JValue::from(()),
        Loaded::Bool(b) => JValue::from(*b),
        Loaded::Int(i) => int(*i),
        Loaded::Float(f) => JValue::from(*f),
        Loaded::Str(s) | Loaded::Date(s) | Loaded::DateTime(s) => JValue::from(s.as_str()),
        Loaded::Seq(items) => PyList::of(items.iter().map(to_template).collect()),
        Loaded::Map(map) => {
            let mut inner = DictInner::default();
            for (k, value) in map.iter() {
                // keys from JSON or a loaded hunt are hashable
                inner
                    .insert(to_template(k), to_template(value))
                    .unwrap_or_default();
            }
            PyDict::of(inner)
        }
    }
}

/// An integer as small as minijinja holds it.
pub fn int(i: i128) -> JValue {
    match i64::try_from(i) {
        Ok(small) => JValue::from(small),
        Err(_) => JValue::from(i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_print_as_python_does() {
        for (f, text) in [
            (1.0, "1.0"),
            (0.1 + 0.2, "0.30000000000000004"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (123456789012345678.0, "1.2345678901234568e+17"),
            (-2.5, "-2.5"),
            (1e22, "1e+22"),
            (-0.0, "-0.0"),
        ] {
            assert_eq!(float_repr(f), text, "{f}");
        }
    }
}
