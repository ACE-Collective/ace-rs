//! Python's text forms: str(float), repr(bytes), str.strip and the exception messages this crate raises.

use crate::XlError;

pub(crate) const NONE_AND: &str = "unsupported operand type(s) for &: 'NoneType' and 'int'";
pub(crate) const NONE_INT: &str = "'NoneType' object cannot be interpreted as an integer";
pub(crate) const CONCAT_NONE: &str = "can only concatenate str (not \"NoneType\") to str";
pub(crate) const NONE_PLUS_STR: &str = "unsupported operand type(s) for +: 'NoneType' and 'str'";
pub(crate) const LIST_RANGE: &str = "list index out of range";
pub(crate) const LIST_ASSIGN_RANGE: &str = "list assignment index out of range";
pub(crate) const NOT_SUBSCRIPTABLE: &str = "'NoneType' object is not subscriptable";

pub(crate) fn type_error(message: &str) -> XlError {
    XlError::new("TypeError", message)
}

pub(crate) fn index_error(message: &str) -> XlError {
    XlError::new("IndexError", message)
}

pub(crate) fn none_attr(attribute: &str) -> XlError {
    XlError::new(
        "AttributeError",
        format!("'NoneType' object has no attribute '{attribute}'"),
    )
}

pub(crate) fn memory_error() -> XlError {
    XlError::new("MemoryError", "")
}

/// Python's str(float): the shortest repr, `1e+16`, `1e-05`, `1.0`.
pub fn float_str(x: f64) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    let sign = if x.is_sign_negative() { "-" } else { "" };
    if x.is_infinite() {
        return format!("{sign}inf");
    }
    // Rust's shortest form gives the digit count, but on a tie between two candidates of that length it
    // rounds up where Python rounds to even. Exact formatting at that length rounds to even, though next
    // to a power of 2 its result can fall outside what parses back to x.
    let shortest = format!("{:e}", x.abs());
    let count = shortest.find('e').unwrap_or(1).saturating_sub(1).max(1);
    let exact = format!("{:.*e}", count - 1, x.abs());
    let chosen = if exact.parse() == Ok(x.abs()) {
        &exact
    } else {
        &shortest
    };
    let (mantissa, exponent) = chosen.split_once('e').unwrap_or((chosen, "0"));
    let digits = mantissa.replace('.', "");
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let decpt = exponent.saturating_add(1);
    if decpt <= -4 || decpt > 16 {
        let (first, rest) = digits.split_at(1);
        let point = if rest.is_empty() { "" } else { "." };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        return format!(
            "{sign}{first}{point}{rest}e{exp_sign}{:02}",
            exponent.unsigned_abs()
        );
    }
    if decpt <= 0 {
        let zeros = "0".repeat(decpt.unsigned_abs() as usize);
        return format!("{sign}0.{zeros}{digits}");
    }
    let whole = decpt.unsigned_abs() as usize;
    if digits.len() <= whole {
        let zeros = "0".repeat(whole.saturating_sub(digits.len()));
        return format!("{sign}{digits}{zeros}.0");
    }
    let (left, right) = digits.split_at(whole);
    format!("{sign}{left}.{right}")
}

/// Python's repr(bytes).
pub(crate) fn bytes_repr(data: &[u8]) -> String {
    let quote = if data.contains(&b'\'') && !data.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(data.len().saturating_add(3));
    out.push('b');
    out.push(quote);
    for &byte in data {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7E => {
                if char::from(byte) == quote {
                    out.push('\\');
                }
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push(quote);
    out
}

/// Python's str.strip() with no argument: Rust's whitespace plus the separators 0x1C to 0x1F.
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

/// Python's str.lower().
pub(crate) fn py_lower(text: &str) -> String {
    text.to_lowercase()
}

/// `'{}'.format(x)` of an optional value.
pub(crate) fn fmt_opt<T: std::fmt::Display>(value: &Option<T>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "None".to_string(),
    }
}

/// convert_to_column_name(n): empty for n <= 0, and n can be negative for a 3D reference.
pub(crate) fn column_name_i64(mut n: i64) -> String {
    let mut name = Vec::new();
    while n > 0 {
        let rest = n - 1;
        name.push(b'A' + (rest % 26) as u8);
        n = rest / 26;
    }
    name.reverse();
    String::from_utf8_lossy(&name).into_owned()
}

/// The column name of a 0-based column.
pub(crate) fn column_name(col: u32) -> String {
    column_name_i64(i64::from(col) + 1)
}
