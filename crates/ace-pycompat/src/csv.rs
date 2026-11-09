//! `csv.reader(io.StringIO(text))` with the default `excel` dialect, a port of CPython 3.14's
//! `Modules/_csv.c` reader.
//!
//! `io.StringIO(text)` has `newline="\n"`: lines end at `\n` only and nothing is translated, so
//! a `\r` outside quotes followed by more of the line raises `_csv.Error` ("new-line character
//! seen in unquoted field ..."). The dialect has `,` for a delimiter, `"` for a quote character
//! (doubled inside quotes), no escape character, `skipinitialspace` off and `strict` off; a NUL is an
//! ordinary character in 3.14. A field may hold at most 131072 characters (`csv.field_size_limit()`).
//!
//! Python's reader yields the rows it has read before it raises, and after an error the next row
//! starts at the line after the one that failed. [`Reader`] is an iterator that does the same: an
//! error is one item, and iteration may go on past it.

use crate::PyErr;

/// `csv.field_size_limit()`'s default.
pub const FIELD_LIMIT: usize = 128 * 1024;

const EOL: u32 = u32::MAX - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    StartRecord,
    StartField,
    InField,
    InQuotedField,
    QuoteInQuotedField,
    EatCrnl,
}

/// `csv.reader(io.StringIO(text))`. Each item is a row, or the `_csv.Error` reading it raised.
pub struct Reader<'a> {
    rest: &'a str,
    state: State,
    field: String,
    field_len: usize,
    fields: Vec<String>,
    line_num: usize,
}

/// `csv.reader(io.StringIO(text))`.
pub fn reader(text: &str) -> Reader<'_> {
    Reader {
        rest: text,
        state: State::StartRecord,
        field: String::new(),
        field_len: 0,
        fields: Vec::new(),
        line_num: 0,
    }
}

/// The rows `for row in csv.reader(io.StringIO(text))` sees before it raises, and the exception,
/// if one is raised.
pub fn read_all(text: &str) -> (Vec<Vec<String>>, Option<PyErr>) {
    let mut rows = Vec::new();
    for row in reader(text) {
        match row {
            Ok(row) => rows.push(row),
            Err(e) => return (rows, Some(e)),
        }
    }
    (rows, None)
}

fn csv_error(message: &str) -> PyErr {
    PyErr::new("_csv", "Error", message)
}

impl<'a> Reader<'a> {
    /// `reader.line_num`: how many lines have been read.
    pub fn line_num(&self) -> usize {
        self.line_num
    }

    fn next_line(&mut self) -> Option<&'a str> {
        if self.rest.is_empty() {
            return None;
        }
        let end = self.rest.find('\n').map_or(self.rest.len(), |i| i + 1);
        let (line, rest) = self.rest.split_at(end);
        self.rest = rest;
        let line: &'a str = line;
        Some(line)
    }

    fn save_field(&mut self) {
        self.fields.push(std::mem::take(&mut self.field));
        self.field_len = 0;
    }

    fn add_char(&mut self, c: char) -> Result<(), PyErr> {
        if self.field_len >= FIELD_LIMIT {
            return Err(csv_error(&format!(
                "field larger than field limit ({FIELD_LIMIT})"
            )));
        }
        self.field.push(c);
        self.field_len += 1;
        Ok(())
    }

    fn process(&mut self, c: u32) -> Result<(), PyErr> {
        let is_nl = c == '\n' as u32 || c == '\r' as u32;
        let ch = || char::from_u32(c).unwrap_or('\u{fffd}');
        if self.state == State::StartRecord {
            if c == EOL {
                return Ok(());
            } else if is_nl {
                self.state = State::EatCrnl;
                return Ok(());
            }
            self.state = State::StartField;
        }
        match self.state {
            State::StartRecord => unreachable!(),
            State::StartField => {
                if is_nl || c == EOL {
                    self.save_field();
                    self.state = if c == EOL {
                        State::StartRecord
                    } else {
                        State::EatCrnl
                    };
                } else if c == '"' as u32 {
                    self.state = State::InQuotedField;
                } else if c == ',' as u32 {
                    self.save_field();
                } else {
                    self.add_char(ch())?;
                    self.state = State::InField;
                }
            }
            State::InField => {
                if is_nl || c == EOL {
                    self.save_field();
                    self.state = if c == EOL {
                        State::StartRecord
                    } else {
                        State::EatCrnl
                    };
                } else if c == ',' as u32 {
                    self.save_field();
                    self.state = State::StartField;
                } else {
                    self.add_char(ch())?;
                }
            }
            State::InQuotedField => {
                if c == EOL {
                } else if c == '"' as u32 {
                    self.state = State::QuoteInQuotedField;
                } else {
                    self.add_char(ch())?;
                }
            }
            State::QuoteInQuotedField => {
                if c == '"' as u32 {
                    self.add_char('"')?;
                    self.state = State::InQuotedField;
                } else if c == ',' as u32 {
                    self.save_field();
                    self.state = State::StartField;
                } else if is_nl || c == EOL {
                    self.save_field();
                    self.state = if c == EOL {
                        State::StartRecord
                    } else {
                        State::EatCrnl
                    };
                } else {
                    self.add_char(ch())?;
                    self.state = State::InField;
                }
            }
            State::EatCrnl => {
                if is_nl {
                } else if c == EOL {
                    self.state = State::StartRecord;
                } else {
                    return Err(csv_error(
                        "new-line character seen in unquoted field - do you need to open the file with newline=''?",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Iterator for Reader<'_> {
    type Item = Result<Vec<String>, PyErr>;

    fn next(&mut self) -> Option<Self::Item> {
        // parse_reset
        self.fields = Vec::new();
        self.field.clear();
        self.field_len = 0;
        self.state = State::StartRecord;
        loop {
            let Some(line) = self.next_line() else {
                if self.field_len != 0 || self.state == State::InQuotedField {
                    self.save_field();
                    break;
                }
                return None;
            };
            self.line_num += 1;
            for c in line.chars() {
                if let Err(e) = self.process(c as u32) {
                    return Some(Err(e));
                }
            }
            if let Err(e) = self.process(EOL) {
                return Some(Err(e));
            }
            if self.state == State::StartRecord {
                break;
            }
        }
        Some(Ok(std::mem::take(&mut self.fields)))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn readers_match_python() {
        let data: Value = crate::testdata::load("csv", include_str!("../tests/data/csv.json"));
        let cases = data.as_array().unwrap();
        assert!(cases.len() > 1000);
        let mut bad = Vec::new();
        for case in cases {
            let text = case["text"].as_str().unwrap();
            // Python's side reads up to 4 items past an error, as the iterator allows.
            let mut items = Vec::new();
            let mut errors = 0;
            for item in reader(text) {
                match item {
                    Ok(row) => items.push(json!({ "row": row })),
                    Err(e) => {
                        items.push(json!({"err": {"module": e.module, "kind": e.kind, "message": e.message}}));
                        errors += 1;
                        if errors == 4 {
                            break;
                        }
                    }
                }
            }
            let got = json!({"text": text, "items": items});
            if &got != case {
                bad.push(format!("got  {got}\nwant {case}"));
            }
        }
        assert!(
            bad.is_empty(),
            "{} of {} differ:\n{}",
            bad.len(),
            cases.len(),
            bad.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
        );
    }

    #[test]
    fn read_all_stops_at_the_first_error() {
        let (rows, err) = read_all("a,b\nc\rd\ne,f\n");
        assert_eq!(rows, vec![vec!["a".to_owned(), "b".to_owned()]]);
        assert_eq!(err.unwrap().kind, "Error");
    }
}
