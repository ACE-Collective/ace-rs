//! `unicodedata` for Unicode 16.0, and the normalization of `unicodedata.ucd_3_2_0`.
//!
//! Normalization ports CPython's `nfd_nfkd` and `nfc_nfkc` (Modules/unicodedata.c) over tables
//! generated from Python (`tables/unicode.py`). `ucd_3_2_0` uses the same decomposition, combining
//! class and composition data as 16.0, except that a code point Unicode 3.2 hadn't assigned doesn't
//! decompose and five code points take ucd_3_2_0's corrections; that is what CPython does too.
//! An ASCII string is returned as it is, as CPython's quick check does.

use std::borrow::Cow;

use crate::tables::unicode as t;
use crate::tables::{in_ranges, lookup, run_value};

/// `unicodedata.category(c)`.
pub fn category(c: char) -> &'static str {
    category_cp(c as u32)
}

/// `unicodedata.category` of a code point, which may be a surrogate.
pub(crate) fn category_cp(cp: u32) -> &'static str {
    t::CATEGORY_NAMES[run_value(t::CATEGORY, cp) as usize]
}

/// `unicodedata.bidirectional(c)`: empty for a code point with no bidirectional class.
pub fn bidirectional(c: char) -> &'static str {
    bidirectional_cp(c as u32)
}

/// `unicodedata.bidirectional` of a code point, which may be a surrogate.
pub(crate) fn bidirectional_cp(cp: u32) -> &'static str {
    t::BIDIRECTIONAL_NAMES[run_value(t::BIDIRECTIONAL, cp) as usize]
}

/// `unicodedata.combining(c)`.
#[inline]
pub fn combining(c: char) -> u8 {
    combining_cp(c as u32)
}

/// `unicodedata.combining` of a code point, which may be a surrogate.
#[inline]
pub(crate) fn combining_cp(cp: u32) -> u8 {
    if cp < 0x300 {
        0
    } else {
        run_value(t::COMBINING, cp)
    }
}

/// Whether `unicodedata.name(c)` has a name for `c` (it raises `ValueError` when it doesn't).
pub fn has_name(c: char) -> bool {
    has_name_cp(c as u32)
}

/// `has_name` of a code point, which may be a surrogate (none has a name).
pub(crate) fn has_name_cp(cp: u32) -> bool {
    !in_ranges(t::NO_NAME, cp)
}

/// A normalization form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    Nfc,
    Nfkc,
    Nfd,
    Nfkd,
}

/// `unicodedata.normalize(form, s)`.
pub fn normalize(form: Form, s: &str) -> Cow<'_, str> {
    normalize_in(form, s, false)
}

/// `unicodedata.normalize("NFC", s)`.
pub fn nfc(s: &str) -> Cow<'_, str> {
    normalize(Form::Nfc, s)
}

/// `unicodedata.normalize("NFKC", s)`.
pub fn nfkc(s: &str) -> Cow<'_, str> {
    normalize(Form::Nfkc, s)
}

/// Whether `unicodedata.normalize("NFKC", c)` differs from `c` and is all ASCII.
pub fn nfkc_maps_to_other_ascii(c: char) -> bool {
    if c.is_ascii() {
        return false;
    }
    let mut buf = [0; 4];
    let n = nfkc(c.encode_utf8(&mut buf));
    n.is_ascii()
}

/// `unicodedata.ucd_3_2_0`.
pub mod ucd_3_2_0 {
    use super::{Form, normalize_in};
    use std::borrow::Cow;

    /// `unicodedata.ucd_3_2_0.normalize(form, s)`.
    pub fn normalize(form: Form, s: &str) -> Cow<'_, str> {
        normalize_in(form, s, true)
    }

    /// `unicodedata.ucd_3_2_0.normalize("NFKC", s)`.
    pub fn nfkc(s: &str) -> Cow<'_, str> {
        normalize(Form::Nfkc, s)
    }
}

fn normalize_in(form: Form, s: &str, v32: bool) -> Cow<'_, str> {
    if s.is_ascii() {
        return Cow::Borrowed(s);
    }
    let d = normalize_cps(form, s.chars().map(|c| c as u32), v32);
    let out: String = d.into_iter().filter_map(char::from_u32).collect();
    if out == s {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(out)
    }
}

/// Normalization over code points, which may include surrogates (they never decompose or compose).
pub(crate) fn normalize_cps(form: Form, cps: impl Iterator<Item = u32>, v32: bool) -> Vec<u32> {
    let (compose, k) = match form {
        Form::Nfc => (true, false),
        Form::Nfkc => (true, true),
        Form::Nfd => (false, false),
        Form::Nfkd => (false, true),
    };
    let d = decompose(cps, k, v32);
    if compose { compose_cps(&d) } else { d }
}

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

fn decomposition(cp: u32, v32: bool) -> Option<(bool, &'static [u32])> {
    if v32 && t::DECOMPOSITION_UNASSIGNED_3_2.binary_search(&cp).is_ok() {
        return None;
    }
    let i = t::DECOMPOSITION
        .binary_search_by_key(&cp, |&(c, _, _)| c)
        .ok()?;
    let (_, compat, parts) = t::DECOMPOSITION[i];
    Some((compat, parts))
}

fn decompose(cps: impl Iterator<Item = u32>, k: bool, v32: bool) -> Vec<u32> {
    let mut out = Vec::with_capacity(cps.size_hint().0);
    let mut stack: Vec<u32> = Vec::new();
    for c in cps {
        stack.push(c);
        while let Some(code) = stack.pop() {
            if (S_BASE..S_BASE + S_COUNT).contains(&code) {
                let s_index = code - S_BASE;
                out.push(L_BASE + s_index / N_COUNT);
                out.push(V_BASE + (s_index % N_COUNT) / T_COUNT);
                let t = T_BASE + s_index % T_COUNT;
                if t != T_BASE {
                    out.push(t);
                }
                continue;
            }
            if v32 && let Some(value) = lookup(t::CORRECTIONS_3_2, code) {
                stack.push(value);
                continue;
            }
            match decomposition(code, v32) {
                Some((compat, parts)) if !compat || k => {
                    stack.extend(parts.iter().rev());
                }
                _ => out.push(code),
            }
        }
    }
    // Sort each run of combining characters by class; CPython's sorts are stable.
    let mut i = 0;
    while i < out.len() {
        if combining_cp(out[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        let mut needs_sort = false;
        let mut prev = combining_cp(out[i]);
        i += 1;
        while i < out.len() {
            let cur = combining_cp(out[i]);
            if cur == 0 {
                break;
            }
            if prev > cur {
                needs_sort = true;
            }
            prev = cur;
            i += 1;
        }
        if needs_sort {
            out[start..i].sort_by_key(|&c| combining_cp(c));
        }
    }
    out
}

fn is_first(cp: u32) -> bool {
    let i = t::COMPOSITION.partition_point(|&(a, _, _)| a < cp);
    i < t::COMPOSITION.len() && t::COMPOSITION[i].0 == cp
}

fn composite(a: u32, b: u32) -> Option<u32> {
    t::COMPOSITION
        .binary_search_by(|&(x, y, _)| (x, y).cmp(&(a, b)))
        .ok()
        .map(|i| t::COMPOSITION[i].2)
}

fn compose_cps(data: &[u32]) -> Vec<u32> {
    let len = data.len();
    let mut output = Vec::with_capacity(len);
    let mut skipped = vec![false; len];
    let mut i = 0;
    while i < len {
        if skipped[i] {
            i += 1;
            continue;
        }
        let mut code = data[i];
        if (L_BASE..L_BASE + L_COUNT).contains(&code)
            && i + 1 < len
            && (V_BASE..V_BASE + V_COUNT).contains(&data[i + 1])
        {
            let l_index = code - L_BASE;
            let v_index = data[i + 1] - V_BASE;
            code = S_BASE + (l_index * V_COUNT + v_index) * T_COUNT;
            i += 2;
            if i < len && T_BASE < data[i] && data[i] < T_BASE + T_COUNT {
                code += data[i] - T_BASE;
                i += 1;
            }
            output.push(code);
            continue;
        }
        if !is_first(code) {
            output.push(code);
            i += 1;
            continue;
        }
        let mut current = code;
        let mut comb = 0;
        let mut i1 = i + 1;
        while i1 < len {
            let code1 = data[i1];
            let comb1 = combining_cp(code1);
            if comb != 0 {
                if comb1 == 0 {
                    break;
                }
                if comb >= comb1 {
                    i1 += 1;
                    continue;
                }
            }
            match composite(current, code1) {
                Some(c) => {
                    current = c;
                    skipped[i1] = true;
                    i1 += 1;
                    if !is_first(current) {
                        break;
                    }
                }
                _ => {
                    if comb1 == 0 {
                        break;
                    }
                    comb = comb1;
                    i1 += 1;
                }
            }
        }
        output.push(current);
        i += 1;
    }
    output
}
