//! The dynamic values evaluate_name_formula computes with, and Python's arithmetic on them.

use crate::formula::{O_BOOL, O_ERR, O_NUM, O_REF, O_REL, O_STRG, Operand};
use crate::py::{R, assertion, complex_repr, err, float_repr, memory_error, py_float, repr_str};

/// Past this a string or list result is MemoryError: doubling through NAME references would
/// otherwise reach any size from a small file.
const MAX_VALUE_LEN: usize = 1 << 26;

/// An element of an oARR value: a float, or a str.
#[derive(Clone, Debug, PartialEq)]
pub enum ArrItem {
    Num(f64),
    Text(String),
}

/// A Ref3D: `rel` of None is the tuple built from coords alone.
#[derive(Clone, Debug, PartialEq)]
pub struct Ref3D {
    pub coords: [i64; 6],
    pub rel: Option<[i64; 6]>,
}

impl Ref3D {
    pub(crate) fn new(coords: [i64; 6], rel: Option<[i64; 6]>) -> Self {
        Ref3D { coords, rel }
    }

    pub(crate) fn repr(&self) -> String {
        let t = |v: &[i64; 6]| {
            format!(
                "({}, {}, {}, {}, {}, {})",
                v[0], v[1], v[2], v[3], v[4], v[5]
            )
        };
        match &self.rel {
            Some(r) if *r != [0; 6] => {
                format!("Ref3D(coords={}, relflags={})", t(&self.coords), t(r))
            }
            _ => format!("Ref3D(coords={})", t(&self.coords)),
        }
    }

    /// tuple comparison key: the tuple holds the relflags when given.
    fn key(&self) -> Vec<i64> {
        let mut v = self.coords.to_vec();
        if let Some(r) = &self.rel {
            v.extend_from_slice(r);
        }
        v
    }
}

#[derive(Clone)]
pub(crate) enum PyVal {
    Int(i64),
    Float(f64),
    Complex(f64, f64),
    Str(String),
    Refs(Vec<Ref3D>),
    Arr(Vec<ArrItem>),
}

fn type_name(v: &PyVal) -> &'static str {
    match v {
        PyVal::Int(_) => "int",
        PyVal::Float(_) => "float",
        PyVal::Complex(..) => "complex",
        PyVal::Str(_) => "str",
        PyVal::Refs(_) | PyVal::Arr(_) => "list",
    }
}

pub(crate) fn arr_repr(a: &[ArrItem]) -> String {
    let parts: Vec<String> = a
        .iter()
        .map(|i| match i {
            ArrItem::Num(f) => float_repr(*f),
            ArrItem::Text(s) => repr_str(s),
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

impl PyVal {
    pub(crate) fn repr(&self) -> String {
        match self {
            PyVal::Int(i) => i.to_string(),
            PyVal::Float(f) => float_repr(*f),
            PyVal::Complex(a, b) => complex_repr(*a, *b),
            PyVal::Str(s) => repr_str(s),
            PyVal::Refs(r) => {
                let parts: Vec<String> = r.iter().map(Ref3D::repr).collect();
                format!("[{}]", parts.join(", "))
            }
            PyVal::Arr(a) => arr_repr(a),
        }
    }

    /// str(value).
    pub(crate) fn str(&self) -> String {
        match self {
            PyVal::Str(s) => s.clone(),
            other => other.repr(),
        }
    }
}

pub(crate) fn binop_kind_rank(opcode: u8) -> (i8, i32) {
    match opcode {
        0x03 | 0x04 => (O_NUM, 30),
        0x05 | 0x06 => (O_NUM, 40),
        0x07 => (O_NUM, 50),
        0x08 => (O_STRG, 20),
        _ => (O_BOOL, 10),
    }
}

pub(crate) fn binop_sym(opcode: u8) -> &'static str {
    match opcode {
        0x03 => "+",
        0x04 => "-",
        0x05 => "*",
        0x06 => "/",
        0x07 => "^",
        0x08 => "&",
        0x09 => "<",
        0x0A => "<=",
        0x0B => "=",
        0x0C => ">=",
        0x0D => ">",
        _ => "<>",
    }
}

pub(crate) fn unop_parts(opcode: u8) -> (i32, &'static str, &'static str) {
    match opcode {
        0x13 => (70, "-", ""),
        0x12 => (70, "+", ""),
        _ => (60, "", "%"),
    }
}

/// evaluate_name_formula's do_binop.
pub(crate) fn do_binop(opcode: u8, stack: &mut Vec<Operand>) -> R<()> {
    if stack.len() < 2 {
        return Err(assertion());
    }
    let bop = stack.pop().ok_or_else(assertion)?;
    let aop = stack.pop().ok_or_else(assertion)?;
    let (result_kind, rank) = binop_kind_rank(opcode);
    let ap = aop.attr("rank")?.rank < rank;
    let bp = bop.attr("rank")?.rank < rank;
    let otext = format!(
        "{}{}{}{}{}{}{}",
        if ap { "(" } else { "" },
        aop.text,
        if ap { ")" } else { "" },
        binop_sym(opcode),
        if bp { "(" } else { "" },
        bop.text,
        if bp { ")" } else { "" },
    );
    let mut res = Operand {
        kind: result_kind,
        value: None,
        rank,
        text: otext,
        bare: false,
    };
    let known = |k: i8| k == O_NUM || k == O_STRG;
    if known(bop.kind)
        && known(aop.kind)
        && let (Some(bv), Some(av)) = (bop.value.as_ref(), aop.value.as_ref())
    {
        res.value = Some(if opcode == 0x08 {
            let (b, a) = (num2strg(bv, bop.kind), num2strg(av, aop.kind));
            if a.len() + b.len() > MAX_VALUE_LEN {
                return Err(memory_error());
            }
            PyVal::Str(a + &b)
        } else if opcode <= 0x07 {
            let b = to_arith(bv, bop.kind)?;
            let a = to_arith(av, aop.kind)?;
            arith(opcode, &a, &b)?
        } else {
            PyVal::Int(i64::from(compare(opcode, av, bv)?))
        });
    }
    stack.push(res);
    Ok(())
}

fn num2strg(v: &PyVal, kind: i8) -> String {
    if kind == O_STRG {
        return v.str();
    }
    let s = v.str();
    match s.strip_suffix(".0") {
        Some(t) => t.to_string(),
        None => s,
    }
}

fn to_arith(v: &PyVal, kind: i8) -> R<PyVal> {
    if kind == O_STRG {
        if let PyVal::Str(s) = v {
            return Ok(PyVal::Float(py_float(s)?));
        }
        return Err(err(
            "TypeError",
            format!(
                "float() argument must be a string or a real number, not '{}'",
                type_name(v)
            ),
        ));
    }
    Ok(v.clone())
}

fn unsupported(sym: &str, a: &PyVal, b: &PyVal) -> crate::XlError {
    err(
        "TypeError",
        format!(
            "unsupported operand type(s) for {sym}: '{}' and '{}'",
            type_name(a),
            type_name(b)
        ),
    )
}

fn as_float(v: &PyVal) -> Option<f64> {
    match v {
        PyVal::Int(i) => Some(*i as f64),
        PyVal::Float(f) => Some(*f),
        _ => None,
    }
}

fn as_complex(v: &PyVal) -> Option<(f64, f64)> {
    match v {
        PyVal::Complex(a, b) => Some((*a, *b)),
        other => as_float(other).map(|f| (f, 0.0)),
    }
}

fn big_int() -> crate::XlError {
    err("OverflowError", "integer result does not fit 64 bits")
}

fn repeat(a: &PyVal, n: i64) -> R<PyVal> {
    let n = n.max(0) as usize;
    match a {
        PyVal::Str(s) => {
            if s.len().saturating_mul(n) > MAX_VALUE_LEN {
                return Err(memory_error());
            }
            Ok(PyVal::Str(s.repeat(n)))
        }
        PyVal::Refs(r) => {
            if r.len().saturating_mul(n) > MAX_VALUE_LEN >> 8 {
                return Err(memory_error());
            }
            Ok(PyVal::Refs(
                std::iter::repeat_n(r, n).flatten().cloned().collect(),
            ))
        }
        PyVal::Arr(r) => {
            if r.len().saturating_mul(n) > MAX_VALUE_LEN >> 8 {
                return Err(memory_error());
            }
            Ok(PyVal::Arr(
                std::iter::repeat_n(r, n).flatten().cloned().collect(),
            ))
        }
        _ => Err(assertion()),
    }
}

fn is_seq(v: &PyVal) -> bool {
    matches!(v, PyVal::Str(_) | PyVal::Refs(_) | PyVal::Arr(_))
}

fn arith(opcode: u8, a: &PyVal, b: &PyVal) -> R<PyVal> {
    match opcode {
        0x03 => add(a, b),
        0x04 => {
            if let (PyVal::Int(x), PyVal::Int(y)) = (a, b) {
                return x.checked_sub(*y).map(PyVal::Int).ok_or_else(big_int);
            }
            if let (Some(x), Some(y)) = (as_float(a), as_float(b)) {
                return Ok(PyVal::Float(x - y));
            }
            match (as_complex(a), as_complex(b)) {
                (Some(x), Some(y)) => Ok(PyVal::Complex(x.0 - y.0, x.1 - y.1)),
                _ => Err(unsupported("-", a, b)),
            }
        }
        0x05 => {
            if let (PyVal::Int(x), PyVal::Int(y)) = (a, b) {
                return x.checked_mul(*y).map(PyVal::Int).ok_or_else(big_int);
            }
            if let (Some(x), Some(y)) = (as_float(a), as_float(b)) {
                return Ok(PyVal::Float(x * y));
            }
            if let (Some(x), Some(y)) = (as_complex(a), as_complex(b)) {
                return Ok(PyVal::Complex(x.0 * y.0 - x.1 * y.1, x.0 * y.1 + x.1 * y.0));
            }
            match (a, b) {
                (s, PyVal::Int(n)) if is_seq(s) => repeat(s, *n),
                (PyVal::Int(n), s) if is_seq(s) => repeat(s, *n),
                (s, o) if is_seq(s) => Err(err(
                    "TypeError",
                    format!(
                        "can't multiply sequence by non-int of type '{}'",
                        type_name(o)
                    ),
                )),
                (o, s) if is_seq(s) => Err(err(
                    "TypeError",
                    format!(
                        "can't multiply sequence by non-int of type '{}'",
                        type_name(o)
                    ),
                )),
                _ => Err(unsupported("*", a, b)),
            }
        }
        0x06 => {
            if let (Some(x), Some(y)) = (as_float(a), as_float(b)) {
                if y == 0.0 {
                    return Err(err("ZeroDivisionError", "division by zero"));
                }
                return Ok(PyVal::Float(x / y));
            }
            match (as_complex(a), as_complex(b)) {
                (Some(x), Some(y)) => {
                    let d = y.0 * y.0 + y.1 * y.1;
                    if d == 0.0 {
                        return Err(err("ZeroDivisionError", "division by zero"));
                    }
                    Ok(PyVal::Complex(
                        (x.0 * y.0 + x.1 * y.1) / d,
                        (x.1 * y.0 - x.0 * y.1) / d,
                    ))
                }
                _ => Err(unsupported("/", a, b)),
            }
        }
        _ => pow(a, b),
    }
}

fn add(a: &PyVal, b: &PyVal) -> R<PyVal> {
    if let (PyVal::Int(x), PyVal::Int(y)) = (a, b) {
        return x.checked_add(*y).map(PyVal::Int).ok_or_else(big_int);
    }
    if let (Some(x), Some(y)) = (as_float(a), as_float(b)) {
        return Ok(PyVal::Float(x + y));
    }
    if let (Some(x), Some(y)) = (as_complex(a), as_complex(b)) {
        return Ok(PyVal::Complex(x.0 + y.0, x.1 + y.1));
    }
    match (a, b) {
        (PyVal::Str(x), PyVal::Str(y)) => {
            if x.len() + y.len() > MAX_VALUE_LEN {
                return Err(memory_error());
            }
            Ok(PyVal::Str(format!("{x}{y}")))
        }
        (PyVal::Refs(x), PyVal::Refs(y)) => {
            if x.len() + y.len() > MAX_VALUE_LEN >> 8 {
                return Err(memory_error());
            }
            let mut v = x.clone();
            v.extend_from_slice(y);
            Ok(PyVal::Refs(v))
        }
        (PyVal::Arr(x), PyVal::Arr(y)) => {
            if x.len() + y.len() > MAX_VALUE_LEN >> 8 {
                return Err(memory_error());
            }
            let mut v = x.clone();
            v.extend_from_slice(y);
            Ok(PyVal::Arr(v))
        }
        (PyVal::Refs(_), PyVal::Arr(_)) | (PyVal::Arr(_), PyVal::Refs(_)) => Err(assertion()),
        (PyVal::Str(_), o) => Err(err(
            "TypeError",
            format!("can only concatenate str (not \"{}\") to str", type_name(o)),
        )),
        (PyVal::Refs(_) | PyVal::Arr(_), o) => Err(err(
            "TypeError",
            format!(
                "can only concatenate list (not \"{}\") to list",
                type_name(o)
            ),
        )),
        _ => Err(unsupported("+", a, b)),
    }
}

fn float_pow(x: f64, y: f64) -> R<PyVal> {
    if y == 0.0 {
        return Ok(PyVal::Float(1.0));
    }
    if x.is_nan() {
        return Ok(PyVal::Float(x));
    }
    if y.is_nan() {
        return Ok(PyVal::Float(if x == 1.0 { x } else { y }));
    }
    if x == 0.0 && y < 0.0 {
        return Err(err("ZeroDivisionError", "zero to a negative power"));
    }
    if x.is_finite() && y.is_finite() && x < 0.0 && y != y.floor() {
        let vabs = x.abs();
        let len = vabs.powf(y);
        let phase = std::f64::consts::PI * y;
        return Ok(PyVal::Complex(len * phase.cos(), len * phase.sin()));
    }
    let r = x.powf(y);
    if r.is_infinite() && x.is_finite() && y.is_finite() {
        return Err(err(
            "OverflowError",
            "(34, 'Numerical result out of range')",
        ));
    }
    Ok(PyVal::Float(r))
}

fn pow(a: &PyVal, b: &PyVal) -> R<PyVal> {
    if let (PyVal::Int(x), PyVal::Int(y)) = (a, b) {
        if *y >= 0 {
            let e = u32::try_from(*y).map_err(|_| big_int())?;
            return x.checked_pow(e).map(PyVal::Int).ok_or_else(big_int);
        }
        return float_pow(*x as f64, *y as f64);
    }
    if let (Some(x), Some(y)) = (as_float(a), as_float(b)) {
        return float_pow(x, y);
    }
    match (as_complex(a), as_complex(b)) {
        (Some(x), Some(y)) => {
            let vabs = x.0.hypot(x.1);
            if vabs == 0.0 {
                if y.1 != 0.0 || y.0 < 0.0 {
                    return Err(err(
                        "ZeroDivisionError",
                        "zero to a negative or complex power",
                    ));
                }
                return Ok(PyVal::Complex(if y.0 == 0.0 { 1.0 } else { 0.0 }, 0.0));
            }
            let mut len = vabs.powf(y.0);
            let at = x.1.atan2(x.0);
            let mut phase = at * y.0;
            if y.1 != 0.0 {
                len /= (at * y.1).exp();
                phase += y.1 * vabs.ln();
            }
            Ok(PyVal::Complex(len * phase.cos(), len * phase.sin()))
        }
        _ => Err(unsupported("** or pow()", a, b)),
    }
}

/// `x < y` and friends; true is 1.
fn compare(opcode: u8, a: &PyVal, b: &PyVal) -> R<bool> {
    use std::cmp::Ordering;
    let sym = binop_sym(opcode);
    let not_ord = || {
        err(
            "TypeError",
            format!(
                "'{sym}' not supported between instances of '{}' and '{}'",
                type_name(a),
                type_name(b)
            ),
        )
    };
    let by_ord = |o: Option<Ordering>| -> bool {
        match opcode {
            0x09 => o == Some(Ordering::Less),
            0x0A => matches!(o, Some(Ordering::Less | Ordering::Equal)),
            0x0B => o == Some(Ordering::Equal),
            0x0C => matches!(o, Some(Ordering::Greater | Ordering::Equal)),
            0x0D => o == Some(Ordering::Greater),
            _ => o != Some(Ordering::Equal),
        }
    };
    let eqne = opcode == 0x0B || opcode == 0x0E;
    match (a, b) {
        (PyVal::Int(x), PyVal::Int(y)) => Ok(by_ord(Some(x.cmp(y)))),
        (PyVal::Str(x), PyVal::Str(y)) => Ok(by_ord(Some(x.cmp(y)))),
        (PyVal::Refs(x), PyVal::Refs(y)) => {
            let k = |v: &[Ref3D]| -> Vec<Vec<i64>> { v.iter().map(Ref3D::key).collect() };
            Ok(by_ord(Some(k(x).cmp(&k(y)))))
        }
        (PyVal::Arr(x), PyVal::Arr(y)) if eqne => {
            Ok(by_ord(if x == y { Some(Ordering::Equal) } else { None }))
        }
        _ => {
            if let (Some(x), Some(y)) = (as_float(a), as_float(b)) {
                return Ok(by_ord(x.partial_cmp(&y)));
            }
            if eqne {
                let eq = match (as_complex(a), as_complex(b)) {
                    (Some(x), Some(y)) => x == y,
                    _ => false,
                };
                return Ok(by_ord(if eq { Some(Ordering::Equal) } else { None }));
            }
            Err(not_ord())
        }
    }
}

/// evaluate_name_formula's do_unaryop.
pub(crate) fn do_unaryop(opcode: u8, stack: &mut Vec<Operand>) -> R<()> {
    let aop = stack.pop().ok_or_else(assertion)?;
    let val = aop.attr("value")?.value.clone();
    let (rank, sym1, sym2) = unop_parts(opcode);
    let lp = aop.rank < rank;
    let otext = format!(
        "{sym1}{}{}{}{sym2}",
        if lp { "(" } else { "" },
        aop.text,
        if lp { ")" } else { "" },
    );
    let value = match val {
        None => None,
        Some(v) => Some(match opcode {
            0x12 => v,
            0x13 => match v {
                PyVal::Int(i) => PyVal::Int(i.checked_neg().ok_or_else(big_int)?),
                PyVal::Float(f) => PyVal::Float(-f),
                PyVal::Complex(a, b) => PyVal::Complex(-a, -b),
                other => {
                    return Err(err(
                        "TypeError",
                        format!("bad operand type for unary -: '{}'", type_name(&other)),
                    ));
                }
            },
            _ => match v {
                PyVal::Int(i) => PyVal::Float(i as f64 / 100.0),
                PyVal::Float(f) => PyVal::Float(f / 100.0),
                PyVal::Complex(a, b) => PyVal::Complex(a / 100.0, b / 100.0),
                other => {
                    return Err(err(
                        "TypeError",
                        format!(
                            "unsupported operand type(s) for /: '{}' and 'float'",
                            type_name(&other)
                        ),
                    ));
                }
            },
        }),
    };
    stack.push(Operand {
        kind: O_NUM,
        value,
        rank,
        text: otext,
        bare: false,
    });
    Ok(())
}

/// tIsect, tList, tRange in evaluate_name_formula. `otext` is already built.
pub(crate) fn box_op(opcode: u8, aop: &Operand, bop: &Operand, otext: String) -> R<Operand> {
    let bk = bop.attr("kind")?.kind;
    let ak = aop.attr("kind")?.kind;
    let mut res = Operand {
        kind: O_REF,
        value: None,
        rank: if opcode == 0x0F { 0 } else { 80 },
        text: otext,
        bare: false,
    };
    let any_err = bk == O_ERR || ak == O_ERR;
    let single_refs = || -> R<Option<(&Ref3D, &Ref3D)>> {
        match (aop.value.as_ref(), bop.value.as_ref()) {
            (Some(PyVal::Refs(a)), Some(PyVal::Refs(b))) => {
                if a.len() != 1 || b.len() != 1 {
                    return Err(assertion());
                }
                match (a.first(), b.first()) {
                    (Some(x), Some(y)) => Ok(Some((x, y))),
                    _ => Err(assertion()),
                }
            }
            _ => Ok(None),
        }
    };
    let boxed = |a: &Ref3D, b: &Ref3D| -> [i64; 6] {
        let mut c = [0i64; 6];
        for (i, (x, y)) in a.coords.iter().zip(b.coords.iter()).enumerate() {
            // tRangeFuncs is (min, max, ...) and tIsectFuncs (max, min, ...).
            let min_here = (i % 2 == 0) == (opcode == 0x11);
            if let Some(slot) = c.get_mut(i) {
                *slot = if min_here { *x.min(y) } else { *x.max(y) };
            }
        }
        c
    };
    match opcode {
        0x0F | 0x11 => {
            if any_err {
                if opcode == 0x11 {
                    let mut e = res;
                    e.bare = true;
                    e.kind = O_ERR;
                    return Ok(e);
                }
                res.kind = O_ERR;
            } else if opcode == 0x0F && (bk == 0 || ak == 0) {
            } else if bk == O_REF && ak == O_REF {
                if let Some((a, b)) = single_refs()? {
                    res.value = Some(PyVal::Refs(vec![Ref3D::new(boxed(a, b), None)]));
                }
            } else if bk == O_REL && ak == O_REL {
                res.kind = O_REL;
                if let Some((a, b)) = single_refs()? {
                    let rel = |r: &Ref3D| r.rel.unwrap_or([0; 6]);
                    if rel(a) == rel(b) {
                        res.value = Some(PyVal::Refs(vec![Ref3D::new(boxed(a, b), Some(rel(a)))]));
                    }
                }
            }
        }
        _ => {
            let is_ref = |k: i8| k == O_REF || k == O_REL;
            if any_err {
                res.kind = O_ERR;
            } else if is_ref(bk) && is_ref(ak) {
                res.kind = if ak == O_REL || bk == O_REL {
                    O_REL
                } else {
                    O_REF
                };
                if let (Some(PyVal::Refs(a)), Some(PyVal::Refs(b))) =
                    (aop.value.as_ref(), bop.value.as_ref())
                {
                    if a.is_empty() || b.len() != 1 {
                        return Err(assertion());
                    }
                    let mut v = a.clone();
                    v.extend_from_slice(b);
                    res.value = Some(PyVal::Refs(v));
                }
            }
        }
    }
    Ok(res)
}

/// `value in (0, 1)`; None is not in.
pub(crate) fn in_zero_one(v: Option<&PyVal>) -> bool {
    match v {
        Some(PyVal::Int(i)) => *i == 0 || *i == 1,
        Some(PyVal::Float(f)) => *f == 0.0 || *f == 1.0,
        Some(PyVal::Complex(a, b)) => *b == 0.0 && (*a == 0.0 || *a == 1.0),
        _ => false,
    }
}

pub(crate) fn truthy(v: &PyVal) -> bool {
    match v {
        PyVal::Int(i) => *i != 0,
        PyVal::Float(f) => *f != 0.0,
        PyVal::Complex(a, b) => *a != 0.0 || *b != 0.0,
        PyVal::Str(s) => !s.is_empty(),
        PyVal::Refs(r) => !r.is_empty(),
        PyVal::Arr(r) => !r.is_empty(),
    }
}

pub(crate) fn to_int(v: &PyVal) -> R<i64> {
    match v {
        PyVal::Int(i) => Ok(*i),
        PyVal::Float(f) => Ok(f.trunc() as i64),
        other => Err(err(
            "TypeError",
            format!(
                "int() argument must be a string, a bytes-like object or a real number, not '{}'",
                type_name(other)
            ),
        )),
    }
}

/// CHOOSE's `1 <= value < nargs`.
pub(crate) fn choose_in_range(v: Option<&PyVal>, nargs: i64) -> R<bool> {
    let f = match v {
        Some(PyVal::Int(i)) => *i as f64,
        Some(PyVal::Float(f)) => *f,
        other => {
            let name = other.map_or("NoneType", type_name);
            return Err(err(
                "TypeError",
                format!("'<=' not supported between instances of 'int' and '{name}'"),
            ));
        }
    };
    Ok(1.0 <= f && f < nargs as f64)
}

/// `res.kind, res.value = chosen.kind, chosen.value`, or number 0 for a missing argument.
pub(crate) fn take_choice(res: &mut Operand, chosen: &Operand) {
    if chosen.kind == 5 {
        res.kind = O_NUM;
        res.value = Some(PyVal::Int(0));
    } else {
        res.kind = chosen.kind;
        res.value.clone_from(&chosen.value);
    }
}
