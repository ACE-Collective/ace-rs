//! Python's `int(bytes)` and `float(bytes)` on header tokens.

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn strip(s: &[u8]) -> &[u8] {
    let a = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    let b = s.iter().rposition(|&c| !is_space(c)).map_or(a, |i| i + 1);
    &s[a..b.max(a)]
}

/// Digits with single underscores between them, as Python's int() and float() allow.
fn digits_ok(s: &[u8]) -> bool {
    !s.is_empty()
        && s[0].is_ascii_digit()
        && s[s.len() - 1].is_ascii_digit()
        && s.iter().all(|&c| c.is_ascii_digit() || c == b'_')
        && !s.windows(2).any(|w| w == b"__")
}

/// `int(token)` (base 10). None is ValueError.
pub(crate) fn py_int(s: &[u8]) -> Option<i128> {
    let s = strip(s);
    let (neg, d) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if !digits_ok(d) {
        return None;
    }
    let mut v: i128 = 0;
    for &c in d {
        if c != b'_' {
            v = v.saturating_mul(10).saturating_add((c - b'0') as i128);
        }
    }
    Some(if neg { -v } else { v })
}

/// `float(token)`. None is ValueError.
pub(crate) fn py_float(s: &[u8]) -> Option<f64> {
    let s = strip(s);
    let text = std::str::from_utf8(s).ok()?;
    let lower = text.to_ascii_lowercase();
    let body = lower.trim_start_matches(['+', '-']);
    if lower.len() - body.len() > 1 {
        return None;
    }
    if matches!(body, "inf" | "infinity" | "nan") {
        return lower
            .parse::<f64>()
            .ok()
            .or(Some(if lower.starts_with('-') {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }));
    }
    // mantissa [e exponent], each digit run allowing single underscores
    let (mant, exp) = match body.find('e') {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let (ip, fp) = match mant.find('.') {
        Some(i) => (&mant[..i], Some(&mant[i + 1..])),
        None => (mant, None),
    };
    if ip.is_empty() && fp.is_none_or(|f| f.is_empty()) {
        return None;
    }
    if !ip.is_empty() && !digits_ok(ip.as_bytes()) {
        return None;
    }
    if let Some(f) = fp {
        if !f.is_empty() && !digits_ok(f.as_bytes()) {
            return None;
        }
    }
    if let Some(e) = exp {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        if !digits_ok(e.as_bytes()) {
            return None;
        }
    }
    lower.replace('_', "").parse::<f64>().ok()
}
