//! A port of LnkParse3 1.6.0 as ace3's `lnk_parser` module uses it
//! (`saq/modules/file_analysis/lnk_parser.py`).
//!
//! The module calls `LnkParse3.lnk_file(fp)`, then `lnk.get_json(get_all=True)` and
//! `lnk.lnk_command`, writes the JSON to `{file}.lnkparser.json`, and on any exception stores
//! `str(e)` as the error. [`analyze`] runs the same steps on bytes. [`LnkFile`] gives each step.
//!
//! Departures from Python:
//! - The property store (METADATA_PROPERTIES_BLOCK) may decode at most 256 MiB of text per
//!   file. Overlapping property values can make Python decode the same bytes again and again,
//!   which grows with the square of the input; past the budget this raises `MemoryError` (with
//!   an empty message, as Python's would have) where Python keeps going until memory runs out.
//!
//! Bounds: no recursion on input data (IDLists nest one level, inside a UsersFilesFolder item
//! or a ShellItem block), and every allocation is a slice of the input, a string decoded from
//! one, or a list with at most one entry per input byte.

mod lnk;
mod text;
mod time;
mod value;

pub use lnk::LnkFile;
pub use value::{DateTime, Dict, PyValue, dump_lnkparser_json, to_ace3_json};

/// A Python exception: its type name and `str(e)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyError {
    /// `type(e).__name__`: `error` (struct.error), `LnkParserError`, `IndexError`,
    /// `TypeError`, `RuntimeError` or `MemoryError`.
    pub kind: &'static str,
    /// `str(e)`.
    pub message: String,
}

impl PyError {
    pub(crate) fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn struct_error(n: usize) -> Self {
        Self::new("error", format!("unpack requires a buffer of {n} bytes"))
    }
}

impl std::fmt::Display for PyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PyError {}

/// What the module leaves after running on one file.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// `analysis.info`: `get_json`'s value, or the initial `{}` when parsing or `get_json`
    /// raised. It is set even when `lnk_command` raises afterwards.
    pub info: PyValue,
    /// `analysis.command`, when `lnk_command` returned. ace3 doesn't serialize it.
    pub command: Option<String>,
    /// `analysis.error`: the exception, if one was raised.
    pub error: Option<PyError>,
    /// The text of `{file}.lnkparser.json`. The module writes and adds the file only when no
    /// exception came before the dump, and the dump itself can't fail on LnkParse3's output.
    pub lnkparser_json: Option<String>,
}

impl Outcome {
    /// `analysis.details` as ace3 stores it: `{"error": ..., "info": ...}` through
    /// `_JSONEncoder`. serde_json's map sorts the keys.
    pub fn details_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert(
            "error".to_owned(),
            self.error
                .as_ref()
                .map_or(serde_json::Value::Null, |e| e.message.clone().into()),
        );
        m.insert("info".to_owned(), to_ace3_json(&self.info));
        serde_json::Value::Object(m)
    }
}

/// The module's `execute_analysis` steps on a file holding `data`.
pub fn analyze(data: &[u8]) -> Outcome {
    let mut out = Outcome {
        info: PyValue::Dict(Dict::new()),
        command: None,
        error: None,
        lnkparser_json: None,
    };
    let lnk = match LnkFile::parse(data) {
        Ok(l) => l,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    match lnk.get_json() {
        Ok(v) => out.info = v,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    }
    match lnk.lnk_command() {
        Ok(c) => out.command = Some(c),
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    }
    out.lnkparser_json = Some(dump_lnkparser_json(&out.info));
    out
}

#[cfg(test)]
mod oracle_tests;
