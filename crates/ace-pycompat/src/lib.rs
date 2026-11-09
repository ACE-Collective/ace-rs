//! Python behaviour that ported code needs, as ace3's image runs it: Python 3.14.10 with
//! unicodedata 16.0.0, idna 3.20, validators 0.36.0 and tld 0.13.2.
//!
//! Each module ports one Python module or package, line by line, quirks and error paths included,
//! because a port's output is compared with ace3's byte for byte:
//!
//! - [`pystr`] is `str` methods (`isspace`, `strip`, `splitlines`, `lower`, ...) and `bytes.decode`.
//! - [`unicodedata`] is `category`, `bidirectional`, `combining` and `normalize`, for Unicode 16.0
//!   and for `ucd_3_2_0`.
//! - [`parse`] is `urllib.parse`.
//! - [`html`] is `html.escape` and `html.unescape`, with `html.entities`.
//! - [`base64`] is `b64decode` and `urlsafe_b64decode`.
//! - [`ipaddress`] is `ip_address`, `IPv4Address` and `IPv6Address`.
//! - [`json`] is `json.loads`.
//! - [`csv`] is `csv.reader` over `io.StringIO`.
//! - [`codecs_idna`] is the `idna` codec (IDNA 2003, nameprep, punycode).
//! - [`idna`] is the idna package's `encode` and `decode` (IDNA 2008).
//! - [`validators`] is `url`, `email` and `domain`.
//! - [`tld`] is `get_tld`, with the list the package bundles.
//!
//! Where Python raises, a function returns a [`PyErr`] naming the exception's class, so a caller can
//! catch what Python's caller catches and let the rest propagate.
//!
//! The Unicode tables in `src/tables` are generated from that Python by the scripts in `tables/`,
//! run in ace3's dev container (`tables/run`). The tests compare each function with Python on case
//! files the scripts in `tables/` also write (`tables/cases`). The committed ones in `tests/data`
//! are samples: every hand-written case, the generated cases that cover each outcome and exception,
//! and some random ones. `ACE_PYCOMPAT_FULL=1 tables/cases` writes the full sets, thousands of
//! cases each, to `tests/full` (git-ignored), and `ACE_PYCOMPAT_CASES=tests/full`
//! in the dev container makes `cargo test -p ace-pycompat` use them. `src/tld/effective_tld_names.dat.txt` is the
//! Public Suffix List as tld 0.13.2 bundles it, byte for byte; it is under the Mozilla Public
//! License 2.0 (<https://mozilla.org/MPL/2.0/>).

pub mod base64;
pub mod codecs_idna;
pub mod csv;
pub mod html;
pub mod idna;
pub mod ipaddress;
pub mod json;
pub mod parse;
pub mod pystr;
pub mod repr;
pub mod tld;
pub mod unicodedata;
pub mod validators;

mod tables;

#[cfg(test)]
mod testdata;

use std::fmt;

/// A Python exception: its class, as `type(e).__module__` and `type(e).__name__`, and `str(e)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyErr {
    /// The class's module, such as `builtins`, `binascii` or `idna.core`.
    pub module: &'static str,
    /// The class's name, such as `ValueError`.
    pub kind: &'static str,
    /// `str(e)`.
    pub message: String,
}

impl PyErr {
    /// An exception of class `module.kind`.
    pub fn new(module: &'static str, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            module,
            kind,
            message: message.into(),
        }
    }

    /// A built-in exception, such as `ValueError`.
    pub fn builtin(kind: &'static str, message: impl Into<String>) -> Self {
        Self::new("builtins", kind, message)
    }

    /// `ValueError(message)`.
    pub fn value_error(message: impl Into<String>) -> Self {
        Self::builtin("ValueError", message)
    }

    /// Whether `except module.kind` catches this exception, by the classes' hierarchy in Python.
    /// `is_instance("builtins", "ValueError")` holds for a `UnicodeError` or a `binascii.Error`.
    pub fn is_instance(&self, module: &str, kind: &str) -> bool {
        let mut class = Some((self.module, self.kind));
        while let Some((m, k)) = class {
            if m == module && k == kind {
                return true;
            }
            class = parent(m, k);
        }
        false
    }

    /// The class's name as a traceback prints it: `ValueError`, or `binascii.Error`.
    pub fn qualified_name(&self) -> String {
        if self.module == "builtins" {
            self.kind.to_owned()
        } else {
            format!("{}.{}", self.module, self.kind)
        }
    }
}

impl fmt::Display for PyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            f.write_str(&self.qualified_name())
        } else {
            write!(f, "{}: {}", self.qualified_name(), self.message)
        }
    }
}

impl std::error::Error for PyErr {}

/// The base class of each exception class this crate raises.
fn parent(module: &str, kind: &str) -> Option<(&'static str, &'static str)> {
    Some(match (module, kind) {
        ("builtins", "BaseException") => return None,
        ("builtins", "Exception") => ("builtins", "BaseException"),
        (
            "builtins",
            "ValueError" | "ArithmeticError" | "RuntimeError" | "TypeError" | "OSError",
        ) => ("builtins", "Exception"),
        ("builtins", "UnicodeError") => ("builtins", "ValueError"),
        ("builtins", "UnicodeEncodeError" | "UnicodeDecodeError") => ("builtins", "UnicodeError"),
        ("builtins", "OverflowError") => ("builtins", "ArithmeticError"),
        ("builtins", "RecursionError") => ("builtins", "RuntimeError"),
        ("binascii", "Error") => ("builtins", "ValueError"),
        ("_csv", "Error") => ("builtins", "Exception"),
        ("json.decoder", "JSONDecodeError") => ("builtins", "ValueError"),
        ("ipaddress", "AddressValueError" | "NetmaskValueError") => ("builtins", "ValueError"),
        ("idna.core", "IDNAError") => ("builtins", "UnicodeError"),
        ("idna.core", "IDNABidiError" | "InvalidCodepoint" | "InvalidCodepointContext") => {
            ("idna.core", "IDNAError")
        }
        ("tld.exceptions", "TldBadUrl" | "TldDomainNotFound") => ("builtins", "ValueError"),
        _ => ("builtins", "Exception"),
    })
}

#[cfg(test)]
mod tests {
    use super::PyErr;

    #[test]
    fn the_hierarchy_is_pythons() {
        let e = PyErr::new("idna.core", "InvalidCodepoint", "x");
        assert!(e.is_instance("idna.core", "IDNAError"));
        assert!(e.is_instance("builtins", "UnicodeError"));
        assert!(e.is_instance("builtins", "ValueError"));
        assert!(!e.is_instance("builtins", "UnicodeEncodeError"));
        let e = PyErr::builtin("OverflowError", "x");
        assert!(!e.is_instance("builtins", "ValueError"));
        assert!(e.is_instance("builtins", "Exception"));
        let e = PyErr::new("binascii", "Error", "Incorrect padding");
        assert!(e.is_instance("builtins", "ValueError"));
        assert_eq!(e.to_string(), "binascii.Error: Incorrect padding");
        assert!(!PyErr::new("_csv", "Error", "x").is_instance("builtins", "ValueError"));
    }
}
