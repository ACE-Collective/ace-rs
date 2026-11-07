//! A port of `pdf-parser.py` 0.7.12 by Didier Stevens, public domain, as ace3 runs it:
//! `python3 pdf-parser.py -f -w -v -c --debug FILE` (`ace3/saq/modules/file_analysis/pdf.py`).
//!
//! YARA rules read this output (`.pdfparser`, `type=document.pdf.object`), so it has to be the same
//! bytes, and those come from how the script reads a file rather than from what a PDF means. So
//! this keeps the script's own tokenizer and state machines, including what they get wrong, and
//! libqpdf isn't involved. `tools/library-diff/run pdf-parser` holds it to the script, byte for byte.
//!
//! What follows from the script being Python 3:
//!
//! - It reads bytes into `str` one `chr()` at a time, so text is Latin-1, and `print` writes it as
//!   UTF-8. A token here is a range of the input, which `Out::text` encodes that way.
//! - A stream comes back as `str` or `bytes`. `' %s' % data` prints the first as itself and the
//!   second as its `repr`, `b'...'`. Hence `Stream`.
//! - Its error paths are often broken. `e.message` doesn't exist in Python 3, so a failed
//!   FlateDecode ends the script with a traceback, and running off the end of the file in several
//!   places does too. That's `Stop::Crash`: the output so far stands, the exit code is 1 and
//!   stderr isn't empty, which is how ace3 sees it.
//! - Python's recursion limit ends the script on deeply nested dictionaries. `frames` counts
//!   Python's frames to crash at the same depth.
//! - The first two lines say this Python hasn't been tested. ace3 runs 3.14.10.
//!
//! Unlike the script, this has limits of its own, in `Limits`. ace3 stops the script after 10
//! seconds and scans what it wrote. A Rust port gets far further in that time, so it's bounded by
//! the bytes it makes as well. Past a limit it stops the same way: `Stop::Limit`, with the output
//! so far.

use std::time::{Duration, Instant};

const CHAR_WHITESPACE: u8 = 1;
const CHAR_DELIMITER: u8 = 2;
const CHAR_REGULAR: u8 = 3;

/// What the script prints first, from `TestPythonVersion`.
const VERSION_WARNING: &[u8] = b"This program has not been tested with this version of Python (3.14.10)\nShould you encounter problems, please use Python version 3.12.2\n";

/// `sys.getrecursionlimit()`.
const RECURSION_LIMIT: usize = 1000;
/// `sys.get_int_max_str_digits()`: `int()` refuses more digits than this.
const INT_MAX_STR_DIGITS: usize = 4300;

/// The bounds on one run.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// ace3's `PDFPARSER_TIMEOUT_SECONDS`.
    pub time: Duration,
    /// The most output it keeps.
    pub output_bytes: usize,
    /// The most bytes one stream may decode to, at any stage of its filters.
    pub decoded_bytes: usize,
    /// The most tokens one object or trailer may hold. A file of delimiters is one token per byte.
    pub object_tokens: usize,
}

impl Limits {
    /// What a task uses. The script reads about 3 MB of a file in ace3's 10 s, so it writes far less
    /// than 64 MiB unless a stream decodes to it. A 240 MiB file took down a bucket with a memory
    /// limit of 1 GiB when it was uploaded (`docs/measurements/pdf-hostile.md`).
    /// 16 M tokens take 192 MiB, and an object's printing copies them twice more.
    pub const TASK: Limits = Limits {
        time: Duration::from_secs(10),
        output_bytes: 64 * 1024 * 1024,
        decoded_bytes: 256 * 1024 * 1024,
        object_tokens: 16 * 1024 * 1024,
    };
}

/// Why a run ended early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The script would have ended with a traceback, which names this exception.
    Crash(&'static str),
    /// A limit in `Limits`.
    Limit(&'static str),
}

/// What a run gave: the script's stdout, and how it ended if not normally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub stdout: Vec<u8>,
    pub stopped: Option<Stop>,
}

impl Run {
    /// The script's exit code. A run stopped by a limit is one ace3's timeout would have killed,
    /// and ace3 doesn't read the code of that.
    pub fn exit(&self) -> i32 {
        match self.stopped {
            Some(Stop::Crash(_)) => 1,
            _ => 0,
        }
    }

    /// Whether the script wrote to stderr: its only writes there are tracebacks.
    pub fn stderr(&self) -> bool {
        matches!(self.stopped, Some(Stop::Crash(_)))
    }
}

/// Runs the script's logic on a file's bytes. A file whose name ends in `.zip` is the first member
/// of that zip, as the script reads it: see `source_of`.
pub fn run(data: &[u8], limits: &Limits) -> Run {
    let mut out = Out::new(limits);
    let stopped = out.bytes(VERSION_WARNING).err().or_else(|| {
        let mut parser = Parser::new(data, &mut out, limits);
        parser.main().err()
    });
    Run {
        stdout: out.buffer,
        stopped,
    }
}

/// `cPDFDocument`'s handling of a file named `*.zip`: it opens the zip's first member with the
/// password `infected`. A file that fails prints two lines and the script exits 0, which a caller
/// reports with `failed_zip`. pyzipper isn't installed in ace3, so this is Python's own zipfile.
pub fn first_zip_member(data: &[u8], limits: &Limits) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))
        .map_err(|_| "File is not a zip file".to_owned())?;
    if archive.is_empty() {
        return Err("list index out of range".to_owned());
    }
    // zipfile knows AES only as a compression method, 99, that it doesn't have
    let raw = archive.by_index_raw(0).map_err(|e| e.to_string())?;
    let readable = matches!(
        raw.compression(),
        zip::CompressionMethod::Stored
            | zip::CompressionMethod::Deflated
            | zip::CompressionMethod::Bzip2
            | zip::CompressionMethod::Lzma
    );
    if !readable
        || raw
            .extra_data_fields()
            .any(|field| matches!(field, zip::ExtraField::AeXEncryption(_)))
    {
        return Err("That compression method is not supported".to_owned());
    }
    drop(raw);
    let mut member = archive
        .by_index_decrypt(0, b"infected")
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    member
        .by_ref()
        .take(limits.decoded_bytes as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// The script's output when it can't open a file: `print('Error opening file %s' % file)`, the
/// exception, and `sys.exit()`.
pub fn failed_zip(path: &str, message: &str) -> Run {
    let mut stdout = VERSION_WARNING.to_vec();
    stdout.extend_from_slice(format!("Error opening file {path}\n{message}\n").as_bytes());
    Run {
        stdout,
        stopped: None,
    }
}

/// Bytes that are Latin-1 text, as the script's `str` holds them.
fn class(byte: u8) -> u8 {
    match byte {
        0 | 9 | 10 | 12 | 13 | 32 => CHAR_WHITESPACE,
        0x28 | 0x29 | 0x3C | 0x3E | 0x5B | 0x5D | 0x7B | 0x7D | 0x2F | 0x25 => CHAR_DELIMITER,
        _ => CHAR_REGULAR,
    }
}

/// `str.isspace` over Latin-1.
fn py_space(byte: u8) -> bool {
    matches!(byte, 9..=13 | 28..=32 | 0x85 | 0xA0)
}

fn py_strip(text: &[u8]) -> &[u8] {
    let start = text
        .iter()
        .position(|b| !py_space(*b))
        .unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|b| !py_space(*b))
        .map_or(start, |p| p + 1);
    &text[start..end]
}

fn py_rstrip(text: &[u8]) -> &[u8] {
    let end = text
        .iter()
        .rposition(|b| !py_space(*b))
        .map_or(0, |p| p + 1);
    &text[..end]
}

/// `repr` of a `str` holding Latin-1.
fn str_repr(text: &[u8]) -> Vec<u8> {
    let quote = if text.contains(&b'\'') && !text.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = vec![quote];
    for &byte in text {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            _ if byte == quote => {
                out.push(b'\\');
                out.push(quote);
            }
            // what str.isprintable refuses, below U+0100
            0..=0x1F | 0x7F..=0xA0 | 0xAD => {
                out.extend_from_slice(format!("\\x{byte:02x}").as_bytes());
            }
            _ => out.push(byte),
        }
    }
    out.push(quote);
    out
}

/// What `bytes_repr` writes for one byte, as many bytes as it takes.
fn push_repr_byte(out: &mut Vec<u8>, byte: u8, quote: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match byte {
        b'\\' => out.extend_from_slice(b"\\\\"),
        b'\t' => out.extend_from_slice(b"\\t"),
        b'\n' => out.extend_from_slice(b"\\n"),
        b'\r' => out.extend_from_slice(b"\\r"),
        _ if byte == quote => out.extend_from_slice(&[b'\\', quote]),
        0x20..=0x7E => out.push(byte),
        _ => out.extend_from_slice(&[
            b'\\',
            b'x',
            HEX[usize::from(byte >> 4)],
            HEX[usize::from(byte & 0x0F)],
        ]),
    }
}

/// How long `bytes_repr` of this is, to know before making it.
fn bytes_repr_len(data: &[u8]) -> usize {
    let quote = repr_quote(data);
    let escapes: usize = data
        .iter()
        .map(|&byte| match byte {
            b'\\' | b'\t' | b'\n' | b'\r' => 1,
            _ if byte == quote => 1,
            0x20..=0x7E => 0,
            _ => 3,
        })
        .sum();
    data.len() + escapes + 3
}

/// The quote `repr` picks.
fn repr_quote(data: &[u8]) -> u8 {
    if data.contains(&b'\'') && !data.contains(&b'"') {
        b'"'
    } else {
        b'\''
    }
}

/// `repr` of a `bytes`, which is ASCII.
pub fn bytes_repr(data: &[u8]) -> Vec<u8> {
    let quote = repr_quote(data);
    let mut out = Vec::with_capacity(bytes_repr_len(data));
    out.push(b'b');
    out.push(quote);
    for &byte in data {
        push_repr_byte(&mut out, byte, quote);
    }
    out.push(quote);
    out
}

/// `re.match('^[0-9]+', text)`.
fn is_numeric(text: &[u8]) -> bool {
    text.first().is_some_and(u8::is_ascii_digit)
}

/// `'%d' % int(text, 10)` for text `is_numeric` accepted. Python takes surrounding whitespace and
/// single underscores between digits, and has no upper bound but its digit limit.
fn py_int(text: &[u8]) -> Result<String, Stop> {
    let invalid = Stop::Crash("ValueError");
    let stripped = py_strip(text);
    let mut digits = Vec::with_capacity(stripped.len());
    let mut after_underscore = true;
    for &byte in stripped {
        match byte {
            b'0'..=b'9' => {
                digits.push(byte);
                after_underscore = false;
            }
            b'_' if !after_underscore => after_underscore = true,
            _ => return Err(invalid),
        }
    }
    if after_underscore || digits.len() > INT_MAX_STR_DIGITS {
        return Err(invalid);
    }
    let start = digits.iter().position(|d| *d != b'0');
    Ok(match start {
        Some(start) => String::from_utf8_lossy(&digits[start..]).into_owned(),
        None => "0".to_owned(),
    })
}

/// `int(text, 16)` for two characters of a name, which may have a sign or whitespace.
fn hex_pair(text: &[u8]) -> Option<i32> {
    let stripped = py_strip(text);
    let (negative, digits) = match stripped.first() {
        Some(b'+') => (false, &stripped[1..]),
        Some(b'-') => (true, &stripped[1..]),
        _ => (false, stripped),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value = 0i32;
    for &digit in digits {
        value = value * 16 + (digit as char).to_digit(16)? as i32;
    }
    Some(if negative { -value } else { value })
}

/// `Canonicalize`: `#xx` in a name.
fn canonicalize(text: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if text.first() != Some(&b'/') || !text.contains(&b'#') {
        return text.into();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'#' && i + 2 < text.len() {
            // chr() of a negative number raises, and the script's except keeps the '#'
            match hex_pair(&text[i + 1..i + 3]) {
                Some(value) if value >= 0 => {
                    out.push(value as u8);
                    i += 2;
                }
                _ => out.push(text[i]),
            }
        } else {
            out.push(text[i]);
        }
        i += 1;
    }
    out.into()
}

fn equal_canonical(text: &[u8], name: &[u8]) -> bool {
    canonicalize(text).as_ref() == name
}

/// A token: its class, and where its text is in the input. Every token the script makes is a run
/// of the input's bytes, even those it joins or splits, so one range will do. A file made of
/// delimiters is one token per byte, so these stay small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tok {
    class: u8,
    start: u32,
    end: u32,
}

/// `cPDFTokenizer`, over a range of the input.
struct Tokenizer<'a> {
    data: &'a [u8],
    position: usize,
    end: usize,
    ungot: Vec<Option<Tok>>,
    finished: bool,
}

impl<'a> Tokenizer<'a> {
    fn new(data: &'a [u8], start: usize, end: usize) -> Self {
        Tokenizer {
            data,
            position: start,
            end,
            ungot: Vec::new(),
            finished: false,
        }
    }

    fn peek(&self) -> Option<u8> {
        (self.position < self.end).then(|| self.data[self.position])
    }

    fn tok(&self, class: u8, start: usize) -> Option<Tok> {
        Some(Tok {
            class,
            start: start as u32,
            end: self.position as u32,
        })
    }

    fn token(&mut self) -> Option<Tok> {
        if let Some(token) = self.ungot.pop() {
            return token;
        }
        if self.finished {
            return None;
        }
        let start = self.position;
        let Some(byte) = self.peek() else {
            self.finished = true;
            return None;
        };
        self.position += 1;
        let kind = class(byte);
        if kind == CHAR_WHITESPACE || kind == CHAR_REGULAR {
            while self.peek().is_some_and(|b| class(b) == kind) {
                self.position += 1;
            }
            if self.peek().is_none() {
                self.finished = true;
            }
            return self.tok(kind, start);
        }
        match byte {
            b'<' | b'>' => {
                if self.peek() == Some(byte) {
                    self.position += 1;
                }
                // at the end of the input the script ungets None, and the next call finds it
                self.tok(CHAR_DELIMITER, start)
            }
            b'%' => {
                while let Some(next) = self.peek() {
                    self.position += 1;
                    if next == b'\n' || next == b'\r' {
                        // the byte after either one joins the comment if it's a line feed
                        if self.peek() == Some(b'\n') {
                            self.position += 1;
                        }
                        break;
                    }
                }
                if self.peek().is_none() {
                    self.finished = true;
                }
                self.tok(CHAR_DELIMITER, start)
            }
            _ => self.tok(CHAR_DELIMITER, start),
        }
    }

    fn token_ignore_whitespace(&mut self) -> Option<Tok> {
        let mut token = self.token();
        while token.is_some_and(|t| t.class == CHAR_WHITESPACE) {
            token = self.token();
        }
        token
    }

    fn unget(&mut self, token: Option<Tok>) {
        self.ungot.push(token);
    }
}

/// `cPDFParser.context`.
#[derive(PartialEq, Clone, Copy)]
enum Context {
    None,
    Obj,
    Xref,
    Trailer,
}

/// What `cPDFParser.GetObject` returns.
enum Element {
    Comment(Tok),
    Xref(Vec<Tok>),
    Trailer(Vec<Tok>),
    Startxref(String),
    Indirect(Indirect),
}

/// `cPDFElementIndirectObject`.
struct Indirect {
    id: String,
    version: String,
    content: Vec<Tok>,
}

/// What `Stream` returns.
enum Stream {
    Str(Vec<u8>),
    Bytes(Vec<u8>),
    /// The filters it found, when it never reached `endstream`.
    List(Vec<Tok>),
}

/// The output, as `print` writes it.
struct Out {
    buffer: Vec<u8>,
    limit: usize,
}

impl Out {
    fn new(limits: &Limits) -> Self {
        Out {
            buffer: Vec::new(),
            limit: limits.output_bytes,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Stop> {
        if self.buffer.len() + bytes.len() > self.limit {
            return Err(Stop::Limit("output"));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Latin-1 text, written as UTF-8.
    fn text(&mut self, text: &[u8]) -> Result<(), Stop> {
        if self.buffer.len() + text.len() * 2 > self.limit {
            return Err(Stop::Limit("output"));
        }
        for &byte in text {
            if byte < 0x80 {
                self.buffer.push(byte);
            } else {
                self.buffer.push(0xC0 | (byte >> 6));
                self.buffer.push(0x80 | (byte & 0x3F));
            }
        }
        Ok(())
    }

    fn line(&mut self, text: &[u8]) -> Result<(), Stop> {
        self.text(text)?;
        self.bytes(b"\n")
    }
}

/// A dictionary as `ParseDictionary` leaves it.
type Parsed = Vec<(Vec<u8>, Value)>;

/// The value of a dictionary's key, in `cPDFParseDictionary`.
#[derive(Debug)]
enum Value {
    Items(Vec<Vec<u8>>),
    Dict(Parsed),
    /// A nested dictionary that ran out of tokens.
    None,
}

/// The frames Python has on its stack where the script parses or prints a dictionary. A frame past
/// the limit raises RecursionError.
fn frames(depth: usize) -> Result<(), Stop> {
    if depth > RECURSION_LIMIT {
        Err(Stop::Crash("RecursionError"))
    } else {
        Ok(())
    }
}

/// `cPDFParseDictionary`'s tokens: what's left, front first. Reversed, so that taking one is cheap
/// where the script's `tokens = tokens[1:]` copies the list.
struct DictTokens<'a> {
    data: &'a [u8],
    reversed: Vec<Tok>,
}

impl DictTokens<'_> {
    fn text(&self, token: Tok) -> &[u8] {
        &self.data[token.start as usize..token.end as usize]
    }

    fn front(&self) -> Option<Tok> {
        self.reversed.last().copied()
    }

    fn is_open(&self, token: Tok) -> bool {
        token.class == CHAR_DELIMITER && self.text(token) == b"<<"
    }

    fn is_close(&self, token: Tok) -> bool {
        token.class == CHAR_DELIMITER && self.text(token) == b">>"
    }

    /// `ParseDictionary`. `depth` is the frame it runs in.
    fn parse(&mut self, depth: usize) -> Result<Option<Parsed>, Stop> {
        frames(depth)?;
        let mut state = 0;
        let mut dictionary = Vec::new();
        let mut key: Vec<u8> = Vec::new();
        let mut value: Vec<Vec<u8>> = Vec::new();
        while let Some(token) = self.front() {
            // every pass calls isOpenDictionary first
            frames(depth + 1)?;
            match state {
                0 => {
                    if self.is_open(token) {
                        state = 1;
                    } else {
                        return Ok(None);
                    }
                }
                1 => {
                    if self.is_open(token) {
                        // ignored
                    } else if self.is_close(token) {
                        return Ok(Some(dictionary));
                    } else if token.class != CHAR_WHITESPACE {
                        // ConditionalCanonicalize calls Canonicalize
                        frames(depth + 2)?;
                        key = canonicalize(self.text(token)).into_owned();
                        value = Vec::new();
                        state = 2;
                    }
                }
                _ => {
                    let text = self.text(token).to_vec();
                    let in_array = value.first().is_some_and(|v| v == b"[");
                    let in_string = value.first().is_some_and(|v| v == b"(");
                    if self.is_open(token) {
                        let nested = self.parse(depth + 1)?;
                        // the nested call left its closing token first, for the end of this pass
                        let nested = match nested {
                            Some(items) => Value::Dict(items),
                            None => Value::None,
                        };
                        dictionary.push((std::mem::take(&mut key), nested));
                        state = 1;
                    } else if self.is_close(token) {
                        dictionary.push((std::mem::take(&mut key), Value::Items(value)));
                        return Ok(Some(dictionary));
                    } else if value.is_empty() && token.class == CHAR_WHITESPACE {
                        // skipped
                    } else if (value.is_empty() && text == b"[") || (in_array && text != b"]") {
                        value.push(text);
                    } else if in_array {
                        value.push(text);
                        dictionary.push((
                            std::mem::take(&mut key),
                            Value::Items(std::mem::take(&mut value)),
                        ));
                        state = 1;
                    } else if value.is_empty() && text == b"(" {
                        value.push(text);
                    } else if in_string && text != b")" {
                        if text[0] == b'%' {
                            // the comment's tail goes back on the list as tokens, so that a
                            // parenthesis inside it still counts. The script builds a tokenizer
                            // for it, three frames deep at most.
                            frames(depth + 3)?;
                            let mut inner = Tokenizer::new(
                                self.data,
                                token.start as usize + 1,
                                token.end as usize,
                            );
                            let mut tail = Vec::new();
                            while let Some(next) = inner.token() {
                                tail.push(next);
                            }
                            self.reversed.pop();
                            self.reversed.extend(tail.into_iter().rev());
                            // the pass's own tokens[1:] below takes the comment, which is gone
                            self.reversed.push(token);
                            value.push(b"%".to_vec());
                        } else {
                            value.push(text);
                        }
                    } else if in_string {
                        value.push(text);
                        let mut balanced = 0i64;
                        for item in &value {
                            if item == b"(" {
                                balanced += 1;
                            } else if item == b")" {
                                balanced -= 1;
                            }
                        }
                        if balanced < 0 {
                            // `self.verbose`, which this class doesn't have
                            return Err(Stop::Crash("AttributeError"));
                        }
                        if balanced < 1 {
                            dictionary.push((
                                std::mem::take(&mut key),
                                Value::Items(std::mem::take(&mut value)),
                            ));
                            state = 1;
                        }
                    } else if !value.is_empty() && text[0] == b'/' {
                        dictionary.push((
                            std::mem::take(&mut key),
                            Value::Items(std::mem::take(&mut value)),
                        ));
                        frames(depth + 2)?;
                        key = canonicalize(&text).into_owned();
                        state = 2;
                    } else {
                        frames(depth + 2)?;
                        value.push(canonicalize(&text).into_owned());
                    }
                }
            }
            self.reversed.pop();
        }
        Ok(None)
    }
}

/// `cPDFParseDictionary.__init__`: what `parsed` holds. `depth` is the frame of `__init__`.
fn parse_dictionary(data: &[u8], content: &[Tok], depth: usize) -> Result<Option<Parsed>, Stop> {
    let mut tokens = content;
    while tokens.first().is_some_and(|t| t.class == CHAR_WHITESPACE) {
        tokens = &tokens[1..];
    }
    while tokens.last().is_some_and(|t| t.class == CHAR_WHITESPACE) {
        tokens = &tokens[..tokens.len() - 1];
    }
    let (Some(first), Some(last)) = (tokens.first(), tokens.last()) else {
        return Ok(None);
    };
    let mut parser = DictTokens {
        data,
        reversed: tokens.iter().rev().copied().collect(),
    };
    let closes = parser.is_close(*last)
        || (last.class == CHAR_DELIMITER && py_rstrip(parser.text(*last)).ends_with(b">>"));
    if parser.is_open(*first) && closes {
        parser.parse(depth + 1)
    } else {
        Ok(None)
    }
}

struct Parser<'a, 'o> {
    data: &'a [u8],
    tokens: Tokenizer<'a>,
    out: &'o mut Out,
    limits: Limits,
    started: Instant,
    // these outlast a call of GetObject: a comment in a trailer returns from the middle of it
    context: Context,
    content: Vec<Tok>,
    object_id: String,
    object_version: String,
    tokens_seen: u64,
}

impl<'a, 'o> Parser<'a, 'o> {
    fn new(data: &'a [u8], out: &'o mut Out, limits: &Limits) -> Self {
        Parser {
            data,
            tokens: Tokenizer::new(data, 0, data.len()),
            out,
            limits: *limits,
            started: Instant::now(),
            context: Context::None,
            content: Vec::new(),
            object_id: String::new(),
            object_version: String::new(),
            tokens_seen: 0,
        }
    }

    fn text(&self, token: Tok) -> &'a [u8] {
        &self.data[token.start as usize..token.end as usize]
    }

    /// `'todo N: %d %s' % (token[0], repr(token[1]))`.
    fn todo(&mut self, number: u8, token: Tok) -> Result<(), Stop> {
        let repr = str_repr(self.text(token));
        self.out
            .text(format!("todo {number}: {} ", token.class).as_bytes())?;
        self.out.line(&repr)
    }

    /// `GetObject`, with the script's `self.token2[0]` on the end of the input as a crash.
    fn next_element(&mut self) -> Result<Option<Element>, Stop> {
        const NOT_SUBSCRIPTABLE: Stop = Stop::Crash("TypeError");
        loop {
            self.tokens_seen += 1;
            // no element may ever come, so this can't wait for one
            if self.tokens_seen.is_multiple_of(4096) && self.started.elapsed() > self.limits.time {
                return Err(Stop::Limit("time"));
            }
            if self.content.len() >= self.limits.object_tokens {
                return Err(Stop::Limit("tokens in an object"));
            }
            let token = if self.context == Context::Obj {
                self.tokens.token()
            } else {
                self.tokens.token_ignore_whitespace()
            };
            let Some(token) = token else {
                return Ok(None);
            };
            let text = self.text(token);
            if token.class == CHAR_DELIMITER {
                if text[0] == b'%' {
                    if self.context == Context::Obj {
                        self.content.push(token);
                    } else {
                        return Ok(Some(Element::Comment(token)));
                    }
                } else if text == b"/" {
                    let next = self.tokens.token().ok_or(NOT_SUBSCRIPTABLE)?;
                    if next.class == CHAR_REGULAR {
                        if self.context != Context::None {
                            self.content.push(Tok {
                                class: CHAR_DELIMITER,
                                start: token.start,
                                end: next.end,
                            });
                        } else {
                            // print('todo 1: %s' % (self.token[1] + self.token2[1]))
                            self.out.text(b"todo 1: /")?;
                            self.out.line(self.text(next))?;
                        }
                    } else {
                        self.tokens.unget(Some(next));
                        if self.context != Context::None {
                            self.content.push(token);
                        } else {
                            self.todo(2, token)?;
                        }
                    }
                } else if self.context != Context::None {
                    self.content.push(token);
                } else {
                    self.todo(3, token)?;
                }
            } else if token.class == CHAR_WHITESPACE {
                if self.context != Context::None {
                    self.content.push(token);
                } else {
                    self.todo(4, token)?;
                }
            } else {
                match self.context {
                    Context::Obj => {
                        if text == b"endobj" {
                            self.context = Context::None;
                            return Ok(Some(Element::Indirect(Indirect::new(
                                self.data,
                                std::mem::take(&mut self.object_id),
                                std::mem::take(&mut self.object_version),
                                std::mem::take(&mut self.content),
                            ))));
                        }
                        self.content.push(token);
                    }
                    Context::Trailer => {
                        if text == b"startxref" || text == b"xref" {
                            self.tokens.unget(Some(token));
                            self.context = Context::None;
                            return Ok(Some(Element::Trailer(std::mem::take(&mut self.content))));
                        }
                        self.content.push(token);
                    }
                    Context::Xref => {
                        if text == b"trailer" || text == b"xref" {
                            self.tokens.unget(Some(token));
                            self.context = Context::None;
                            return Ok(Some(Element::Xref(std::mem::take(&mut self.content))));
                        }
                        self.content.push(token);
                    }
                    Context::None => {
                        if is_numeric(text) {
                            let second = self
                                .tokens
                                .token_ignore_whitespace()
                                .ok_or(NOT_SUBSCRIPTABLE)?;
                            if is_numeric(self.text(second)) {
                                let third = self
                                    .tokens
                                    .token_ignore_whitespace()
                                    .ok_or(NOT_SUBSCRIPTABLE)?;
                                if self.text(third) == b"obj" {
                                    self.object_id = py_int(text)?;
                                    self.object_version = py_int(self.text(second))?;
                                    self.context = Context::Obj;
                                } else {
                                    self.tokens.unget(Some(third));
                                    self.tokens.unget(Some(second));
                                    self.todo(6, token)?;
                                }
                            } else {
                                self.tokens.unget(Some(second));
                                self.todo(7, token)?;
                            }
                        } else if text == b"trailer" {
                            self.context = Context::Trailer;
                            self.content = vec![token];
                        } else if text == b"xref" {
                            self.context = Context::Xref;
                            self.content = vec![token];
                        } else if text == b"startxref" {
                            let second = self.tokens.token_ignore_whitespace();
                            match second {
                                Some(second) if is_numeric(self.text(second)) => {
                                    return Ok(Some(Element::Startxref(py_int(
                                        self.text(second),
                                    )?)));
                                }
                                _ => {
                                    self.tokens.unget(second);
                                    self.todo(9, token)?;
                                }
                            }
                        } else {
                            self.todo(10, token)?;
                        }
                    }
                }
            }
        }
    }

    /// `FormatOutput(content, True)`, printed with what comes before it.
    fn joined_line(&mut self, prefix: &[u8], content: &[Tok]) -> Result<(), Stop> {
        self.out.text(prefix)?;
        for token in content {
            self.out.text(self.text(*token))?;
        }
        self.out.bytes(b"\n")
    }

    /// `print(' %s' % FormatOutput(stream, True))`. The line is made whole before any of it prints.
    fn stream_line(&mut self, stream: &Stream) -> Result<(), Stop> {
        match stream {
            Stream::Str(text) => {
                self.out.bytes(b" ")?;
                self.out.text(text)?;
            }
            Stream::Bytes(bytes) => {
                // a stream of NULs is four times its size, so this is known before it's made
                if self.out.buffer.len() + bytes_repr_len(bytes) + 1 > self.limits.output_bytes {
                    return Err(Stop::Limit("output"));
                }
                self.out.bytes(b" ")?;
                self.out.bytes(&bytes_repr(bytes))?;
            }
            Stream::List(filters) => {
                // ''.join(map(lambda x: x[1], data)), of names: each one's second character
                let mut seconds = Vec::with_capacity(filters.len());
                for filter in filters {
                    seconds.push(*self.text(*filter).get(1).ok_or(Stop::Crash("IndexError"))?);
                }
                self.out.bytes(b" ")?;
                self.out.text(&seconds)?;
            }
        }
        self.out.bytes(b"\n")
    }

    fn print_dictionary(
        &mut self,
        dictionary: &[(Vec<u8>, Value)],
        prefix: &[u8],
        depth: usize,
    ) -> Result<(), Stop> {
        // PrettyPrintSub runs in `depth`, and PrettyPrintSubElement one frame in
        frames(depth)?;
        self.out.text(prefix)?;
        self.out.line(b"<<")?;
        for (key, value) in dictionary {
            frames(depth + 1)?;
            let mut line = prefix.to_vec();
            line.extend_from_slice(b"  ");
            line.extend_from_slice(key);
            match value {
                Value::Items(items) if items.is_empty() => self.out.line(&line)?,
                Value::Items(items) => {
                    let reference = items.len() == 3 && {
                        // IsNumeric, and re.match and re._compile under it
                        frames(depth + 4)?;
                        is_numeric(&items[0]) && items[1] == b"0" && items[2] == b"R"
                    };
                    let joined = items.join(if reference { &b" "[..] } else { &b""[..] });
                    let stripped = py_strip(&joined);
                    let repr = str_repr(stripped);
                    let mut plain = vec![b'\''];
                    plain.extend_from_slice(stripped);
                    plain.push(b'\'');
                    line.push(b' ');
                    line.extend_from_slice(if plain == repr { stripped } else { &repr });
                    self.out.line(&line)?;
                }
                Value::Dict(items) if items.is_empty() => self.out.line(&line)?,
                Value::Dict(items) => {
                    self.out.line(&line)?;
                    let mut inner = prefix.to_vec();
                    inner.extend_from_slice(b"    ");
                    self.print_dictionary(items, &inner, depth + 2)?;
                }
                // e[1][0] of None
                Value::None => return Err(Stop::Crash("TypeError")),
            }
        }
        self.out.text(prefix)?;
        self.out.line(b">>")
    }

    /// `object.Stream(filter)`.
    fn stream(&self, object: &Indirect, filter: bool) -> Result<Stream, Stop> {
        #[derive(PartialEq)]
        enum State {
            Start,
            Filter,
            FilterList,
            SearchStream,
            StreamWhitespace,
            StreamConcat,
        }
        let mut state = State::Start;
        let mut count = 0i64;
        let mut data: Vec<u8> = Vec::new();
        let mut filters: Vec<Tok> = Vec::new();
        for token in &object.content {
            let text = self.text(*token);
            let delimiter = token.class == CHAR_DELIMITER;
            let regular = token.class == CHAR_REGULAR;
            match state {
                State::Start => {
                    if delimiter && text == b"<<" {
                        count += 1;
                    }
                    if delimiter && text == b">>" {
                        count -= 1;
                    }
                    if count == 1 && delimiter && equal_canonical(text, b"/Filter") {
                        state = State::Filter;
                    } else if count == 0 && regular && text == b"stream" {
                        state = State::StreamWhitespace;
                    }
                }
                State::Filter => {
                    if delimiter && text[0] == b'/' {
                        filters = vec![*token];
                        state = State::SearchStream;
                    } else if delimiter && text == b"[" {
                        state = State::FilterList;
                    }
                }
                State::FilterList => {
                    if delimiter && text[0] == b'/' {
                        filters.push(*token);
                    } else if delimiter && text == b"]" {
                        state = State::SearchStream;
                    }
                }
                State::SearchStream => {
                    if regular && text == b"stream" {
                        state = State::StreamWhitespace;
                    }
                }
                State::StreamWhitespace => {
                    if token.class == CHAR_WHITESPACE {
                        if text.starts_with(b"\r\n") && text.len() > 2 {
                            data.extend_from_slice(&text[2..]);
                        } else if text.starts_with(b"\n") && text.len() > 1 {
                            data.extend_from_slice(&text[1..]);
                        }
                    } else {
                        data.extend_from_slice(text);
                    }
                    state = State::StreamConcat;
                }
                State::StreamConcat => {
                    if regular && text == b"endstream" {
                        return if filter {
                            self.decompress(data, &filters)
                        } else {
                            Ok(Stream::Str(data))
                        };
                    }
                    data.extend_from_slice(text);
                }
            }
        }
        Ok(Stream::List(filters))
    }

    /// `Decompress`. What it gets is `str` at first, and each filter's result is `str` or `bytes`.
    fn decompress(&self, data: Vec<u8>, filters: &[Tok]) -> Result<Stream, Stop> {
        const FAILED: fn(&str) -> Result<Stream, Stop> = |name| {
            Ok(Stream::Str(
                format!("{name} decompress failed").into_bytes(),
            ))
        };
        let mut current = Stream::Str(data);
        for filter in filters {
            let name = canonicalize(self.text(*filter));
            let name = name.as_ref();
            current = match name {
                b"/FlateDecode" | b"/Fl" => {
                    let input = match &current {
                        Stream::Str(data) | Stream::Bytes(data) => data,
                        Stream::List(_) => unreachable!("a filter's input is never a list"),
                    };
                    match flate_decode(input, self.limits.decoded_bytes) {
                        Inflated::Done(bytes) => Stream::Bytes(bytes),
                        Inflated::TooBig => return Err(Stop::Limit("decoded stream")),
                        // zlib.error: `e.message` doesn't exist in Python 3
                        Inflated::Failed => return Err(Stop::Crash("AttributeError")),
                    }
                }
                b"/ASCIIHexDecode" | b"/AHx" => match &current {
                    Stream::Str(data) => match ascii_hex_decode(data) {
                        Some(bytes) => Stream::Bytes(bytes),
                        None => return FAILED("ASCIIHexDecode"),
                    },
                    // a loop over bytes finds no characters to test only when it's empty
                    Stream::Bytes(data) if data.is_empty() => Stream::Bytes(Vec::new()),
                    _ => return FAILED("ASCIIHexDecode"),
                },
                b"/ASCII85Decode" | b"/A85" => match &current {
                    Stream::Str(data) => match ascii85_decode(data) {
                        Some(bytes) => Stream::Bytes(bytes),
                        None => return FAILED("ASCII85Decode"),
                    },
                    _ => return FAILED("ASCII85Decode"),
                },
                b"/LZWDecode" | b"/LZW" => match &current {
                    Stream::Str(data) => match lzw_decode(data, self.limits.decoded_bytes) {
                        Lzw::Done(text) => Stream::Str(text),
                        Lzw::Failed => return FAILED("LZWDecode"),
                        Lzw::TooBig => return Err(Stop::Limit("decoded stream")),
                    },
                    _ => return FAILED("LZWDecode"),
                },
                b"/RunLengthDecode" | b"/R" => match &current {
                    Stream::Str(data) => match run_length_decode(data, self.limits.decoded_bytes) {
                        Lzw::Done(text) => Stream::Str(text),
                        Lzw::Failed => return FAILED("RunLengthDecode"),
                        Lzw::TooBig => return Err(Stop::Limit("decoded stream")),
                    },
                    _ => return FAILED("RunLengthDecode"),
                },
                _ => {
                    // 'Unsupported filter: %s' % repr(filters)
                    let mut message = b"Unsupported filter: [".to_vec();
                    for (i, each) in filters.iter().enumerate() {
                        if i > 0 {
                            message.extend_from_slice(b", ");
                        }
                        message.extend_from_slice(&str_repr(self.text(*each)));
                    }
                    message.push(b']');
                    return Ok(Stream::Str(message));
                }
            };
        }
        if filters.is_empty() {
            Ok(Stream::Str(b"No filters".to_vec()))
        } else {
            Ok(current)
        }
    }

    /// `PrintOutputObject`, under `-f -w -v -c --debug`.
    fn print_object(&mut self, object: &Indirect) -> Result<(), Stop> {
        // <module>, Main, PrintObject, PrintOutputObject
        const FRAME: usize = 4;
        self.out
            .line(format!("obj {} {}", object.id, object.version).as_bytes())?;
        let kind = object.object_type(self.data);
        self.out.text(b" Type: ")?;
        self.out.line(&canonicalize(&kind))?;
        let references = object.references(self.data);
        self.joined_refs(&references)?;
        let preceding = object.contains_stream(self.data);
        let dictionary = if let Some(preceding) = preceding {
            self.out.line(b" Contains stream")?;
            self.joined_line(b" ", preceding)?;
            parse_dictionary(self.data, preceding, FRAME + 1)?
        } else {
            self.joined_line(b" ", &object.content)?;
            parse_dictionary(self.data, &object.content, FRAME + 1)?
        };
        self.out.bytes(b"\n")?;
        if let Some(dictionary) = &dictionary {
            // PrettyPrint, then PrettyPrintSub
            self.print_dictionary(dictionary, b"  ", FRAME + 2)?;
        }
        self.out.bytes(b"\n")?;
        let filtered = self.stream(object, true)?;
        match &filtered {
            Stream::List(filters) if filters.is_empty() => {
                self.joined_line(b" ", &object.content)?;
            }
            _ => self.stream_line(&filtered)?,
        }
        if object.contains_stream(self.data).is_some() {
            let stream = self.stream(object, false)?;
            if !matches!(&stream, Stream::List(filters) if filters.is_empty()) {
                self.stream_line(&stream)?;
            }
        } else {
            self.joined_line(b"", &object.content)?;
        }
        self.out.bytes(b"\n")
    }

    /// `print(' Referencing: %s' % ', '.join(...))`.
    fn joined_refs(&mut self, references: &[[Tok; 3]]) -> Result<(), Stop> {
        self.out.text(b" Referencing: ")?;
        for (i, [a, b, c]) in references.iter().enumerate() {
            if i > 0 {
                self.out.text(b", ")?;
            }
            self.out.text(self.text(*a))?;
            self.out.text(b" ")?;
            self.out.text(self.text(*b))?;
            self.out.text(b" ")?;
            self.out.text(self.text(*c))?;
        }
        self.out.bytes(b"\n")
    }

    /// `Main`'s loop.
    fn main(&mut self) -> Result<(), Stop> {
        // <module>, Main; then __init__ of cPDFParseDictionary, then PrettyPrint and PrettyPrintSub
        const FRAME: usize = 2;
        while let Some(element) = self.next_element()? {
            if self.started.elapsed() > self.limits.time {
                return Err(Stop::Limit("time"));
            }
            match element {
                Element::Comment(token) => {
                    self.out.text(b"PDF Comment ")?;
                    self.out.line(self.text(token))?;
                    self.out.bytes(b"\n")?;
                }
                Element::Xref(content) => {
                    self.joined_line(b"xref ", &content)?;
                    self.out.bytes(b"\n")?;
                }
                Element::Trailer(content) => {
                    let dictionary = parse_dictionary(self.data, &content[1..], FRAME + 1)?;
                    self.out.line(b"trailer")?;
                    if let Some(dictionary) = &dictionary {
                        self.print_dictionary(dictionary, b"  ", FRAME + 2)?;
                    }
                    self.out.bytes(b"\n")?;
                }
                Element::Startxref(index) => {
                    self.out.line(format!("startxref {index}").as_bytes())?;
                    self.out.bytes(b"\n")?;
                }
                Element::Indirect(object) => self.print_object(&object)?,
            }
        }
        Ok(())
    }
}

impl Indirect {
    /// `cPDFElementIndirectObject.__init__`, with its fix for Ghostscript's streams: an
    /// `endstream` stuck to what comes before it is split off.
    fn new(data: &[u8], id: String, version: String, content: Vec<Tok>) -> Self {
        let mut object = Indirect {
            id,
            version,
            content,
        };
        if object.contains_stream(data).is_none() {
            return object;
        }
        let Some(position) = object
            .content
            .iter()
            .rposition(|t| t.class != CHAR_WHITESPACE)
        else {
            return object;
        };
        let last = object.content[position];
        let text = &data[last.start as usize..last.end as usize];
        if text.ends_with(b"endstream\n") {
            let split = last.end - b"endstream\n".len() as u32;
            object.content[position] = Tok { end: split, ..last };
            object.content.insert(
                position + 1,
                Tok {
                    class: CHAR_REGULAR,
                    start: split,
                    end: split + b"endstream".len() as u32,
                },
            );
            return object;
        }
        if last.class != CHAR_REGULAR || text == b"endstream" || !text.ends_with(b"endstream") {
            return object;
        }
        let split = last.end - b"endstream".len() as u32;
        object.content[position] = Tok { end: split, ..last };
        object.content.insert(
            position + 1,
            Tok {
                class: last.class,
                start: split,
                end: last.end,
            },
        );
        object
    }

    /// `ContainsStream`: what comes before the first `stream`, when that isn't nothing. The script
    /// tests the list it returns for truth, so a `stream` first counts as no stream.
    fn contains_stream(&self, data: &[u8]) -> Option<&[Tok]> {
        let position = self.content.iter().position(|t| {
            t.class == CHAR_REGULAR && &data[t.start as usize..t.end as usize] == b"stream"
        })?;
        (position > 0).then(|| &self.content[..position])
    }

    /// `CopyWithoutWhiteSpace`.
    fn solid(&self) -> Vec<Tok> {
        self.content
            .iter()
            .filter(|t| t.class != CHAR_WHITESPACE)
            .copied()
            .collect()
    }

    /// `GetType`.
    fn object_type(&self, data: &[u8]) -> Vec<u8> {
        let text = |t: Tok| &data[t.start as usize..t.end as usize];
        let content = self.solid();
        let mut dictionary = 0i64;
        for (i, token) in content.iter().enumerate() {
            let delimiter = token.class == CHAR_DELIMITER;
            if delimiter && text(*token) == b"<<" {
                dictionary += 1;
            }
            if delimiter && text(*token) == b">>" {
                dictionary -= 1;
            }
            if dictionary == 1
                && delimiter
                && equal_canonical(text(*token), b"/Type")
                && let Some(next) = content.get(i + 1)
            {
                return text(*next).to_vec();
            }
        }
        Vec::new()
    }

    /// `GetReferences`.
    fn references(&self, data: &[u8]) -> Vec<[Tok; 3]> {
        let text = |t: Tok| &data[t.start as usize..t.end as usize];
        let content = self.solid();
        let mut references = Vec::new();
        for i in 2..content.len() {
            let (a, b, c) = (content[i - 2], content[i - 1], content[i]);
            if c.class == CHAR_REGULAR
                && text(c) == b"R"
                && a.class == CHAR_REGULAR
                && is_numeric(text(a))
                && b.class == CHAR_REGULAR
                && is_numeric(text(b))
            {
                references.push([a, b, c]);
            }
        }
        references
    }
}

enum Inflated {
    Done(Vec<u8>),
    Failed,
    TooBig,
}

/// `zlib.decompress`: it wants a complete stream, and ignores what follows one. The script's
/// fallback calls `decompress` with an int, which raises, so it ends in the first error anyway.
fn flate_decode(input: &[u8], limit: usize) -> Inflated {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut inflate = Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(3).min(1 << 20));
    loop {
        if out.len() == out.capacity() {
            if out.len() >= limit {
                return Inflated::TooBig;
            }
            let more = out.capacity().max(1 << 16).min(limit - out.len());
            out.reserve_exact(more);
        }
        let consumed = inflate.total_in() as usize;
        let before = inflate.total_out();
        match inflate.decompress_vec(&input[consumed..], &mut out, FlushDecompress::None) {
            Ok(Status::StreamEnd) => return Inflated::Done(out),
            Ok(_) => {
                let progress =
                    inflate.total_in() as usize != consumed || inflate.total_out() != before;
                if !progress && out.len() < out.capacity() {
                    return Inflated::Failed;
                }
            }
            Err(_) => return Inflated::Failed,
        }
    }
}

/// `ASCIIHexDecode`: `binascii.unhexlify` of the text without spaces, tabs, line ends and trailing
/// `>`. None for what raises.
fn ascii_hex_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut digits: Vec<u8> = data
        .iter()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .copied()
        .collect();
    while digits.last() == Some(&b'>') {
        digits.pop();
    }
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some((high * 16 + low) as u8)
        })
        .collect()
}

/// `ASCII85Decode(data.rstrip('>'))`. None for what raises: a value `struct.pack('>L')` refuses,
/// and a `z` inside a group, which is an assert.
fn ascii85_decode(data: &[u8]) -> Option<Vec<u8>> {
    let end = data.iter().rposition(|b| *b != b'>').map_or(0, |p| p + 1);
    let mut out = Vec::with_capacity(end / 5 * 4);
    let mut count = 0;
    let mut value: u64 = 0;
    for &c in &data[..end] {
        if (b'!'..=b'u').contains(&c) {
            count += 1;
            value = value * 85 + u64::from(c - 33);
            if count == 5 {
                out.extend_from_slice(&u32::try_from(value).ok()?.to_be_bytes());
                count = 0;
                value = 0;
            }
        } else if c == b'z' {
            if count != 0 {
                return None;
            }
            out.extend_from_slice(&[0; 4]);
        } else if c == b'~' {
            if count > 0 {
                for _ in 0..5 - count {
                    value = value * 85 + 84;
                }
                let bytes = u32::try_from(value).ok()?.to_be_bytes();
                out.extend_from_slice(&bytes[..count - 1]);
            }
            break;
        }
    }
    Some(out)
}

enum Lzw {
    Done(Vec<u8>),
    Failed,
    TooBig,
}

/// `RunLengthDecode`, whose `while runLength:` also stops on a length byte of 0, and whose
/// `ord(f.read(1))` raises at the end of the data.
fn run_length_decode(data: &[u8], limit: usize) -> Lzw {
    let mut out = Vec::new();
    let mut position = 0;
    let next = |position: &mut usize| {
        let byte = data.get(*position).copied();
        *position += 1;
        byte
    };
    let Some(mut length) = next(&mut position) else {
        return Lzw::Failed;
    };
    while length != 0 {
        if length < 128 {
            let start = position.min(data.len());
            let end = (position + length as usize + 1).min(data.len());
            out.extend_from_slice(&data[start..end]);
            position += length as usize + 1;
        }
        if length > 128
            && let Some(byte) = next(&mut position)
        {
            out.resize(out.len() + 257 - length as usize, byte);
        }
        if length == 128 {
            break;
        }
        if out.len() > limit {
            return Lzw::TooBig;
        }
        let Some(following) = next(&mut position) else {
            return Lzw::Failed;
        };
        length = following;
    }
    Lzw::Done(out)
}

/// One entry of `LZWDecoder`'s table: an earlier entry and one more byte. The script keeps each as
/// a whole string, and its table never resets on its own, so a small hostile stream costs it
/// quadratic memory. This costs a few bytes an entry, and only what it writes out is expanded.
#[derive(Clone, Copy)]
struct LzwEntry {
    parent: u32,
    last: u8,
    first: u8,
    length: u32,
}

/// `LZWDecode`.
fn lzw_decode(data: &[u8], limit: usize) -> Lzw {
    const NO_PARENT: u32 = u32::MAX;
    const EMPTY: LzwEntry = LzwEntry {
        parent: NO_PARENT,
        last: 0,
        first: 0,
        length: 0,
    };
    let fresh = || {
        let mut table: Vec<LzwEntry> = (0..=255u8)
            .map(|c| LzwEntry {
                parent: NO_PARENT,
                last: c,
                first: c,
                length: 1,
            })
            .collect();
        table.push(EMPTY);
        table.push(EMPTY);
        table
    };
    let mut table: Option<Vec<LzwEntry>> = None;
    // None until a 256 sets it to empty, and an entry's index from then on
    let mut previous: Option<u32> = None;
    let mut bits_wanted = 9;
    let mut out: Vec<u8> = Vec::new();
    let mut buffer: u32 = 0;
    let mut position_in_byte = 8;
    let mut position = 0;
    let write = |entry: u32, table: &[LzwEntry], out: &mut Vec<u8>| -> bool {
        let length = table[entry as usize].length as usize;
        if out.len() + length > limit {
            return false;
        }
        let start = out.len();
        out.resize(start + length, 0);
        let mut at = start + length;
        let mut current = entry;
        while current != NO_PARENT {
            at -= 1;
            out[at] = table[current as usize].last;
            current = table[current as usize].parent;
        }
        true
    };
    'codes: loop {
        // readbits
        let mut value: u32 = 0;
        let mut wanted = bits_wanted;
        loop {
            let remaining = 8 - position_in_byte;
            if wanted <= remaining {
                value =
                    (value << wanted) | ((buffer >> (remaining - wanted)) & ((1 << wanted) - 1));
                position_in_byte += wanted;
                break;
            }
            value = (value << remaining) | (buffer & ((1 << remaining) - 1));
            wanted -= remaining;
            let Some(&byte) = data.get(position) else {
                break 'codes;
            };
            position += 1;
            buffer = u32::from(byte);
            position_in_byte = 0;
        }
        // feed
        if value == 256 {
            table = Some(fresh());
            previous = Some(NO_PARENT);
            bits_wanted = 9;
        } else if value == 257 {
            // nothing
        } else {
            let empty_previous = previous.is_none() || previous == Some(NO_PARENT);
            if empty_previous {
                // self.table[code], and None[code] raises
                let Some(entries) = table.as_ref() else {
                    return Lzw::Failed;
                };
                if value as usize >= entries.len() {
                    return Lzw::Failed;
                }
                previous = Some(value);
                if !write(value, entries, &mut out) {
                    return Lzw::TooBig;
                }
            } else {
                let Some(entries) = table.as_mut() else {
                    return Lzw::Failed;
                };
                let prev = previous.unwrap_or(NO_PARENT);
                let prev_entry = entries[prev as usize];
                let size = entries.len();
                let appended_last = if (value as usize) < size {
                    entries[value as usize].first
                } else {
                    prev_entry.first
                };
                entries.push(LzwEntry {
                    parent: prev,
                    last: appended_last,
                    first: prev_entry.first,
                    length: prev_entry.length + 1,
                });
                if value as usize >= entries.len() {
                    return Lzw::Failed;
                }
                match entries.len() {
                    511 => bits_wanted = 10,
                    1023 => bits_wanted = 11,
                    2047 => bits_wanted = 12,
                    _ => {}
                }
                previous = Some(value);
                if !write(value, entries, &mut out) {
                    return Lzw::TooBig;
                }
            }
        }
    }
    Lzw::Done(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNLIMITED: Limits = Limits {
        time: Duration::from_secs(600),
        output_bytes: usize::MAX / 4,
        decoded_bytes: 1 << 30,
        object_tokens: usize::MAX,
    };

    fn output(input: &[u8]) -> (String, Option<Stop>) {
        let run = run(input, &UNLIMITED);
        let text = String::from_utf8(run.stdout[VERSION_WARNING.len()..].to_vec()).expect("utf-8");
        (text, run.stopped)
    }

    #[test]
    fn an_object_prints_its_dictionary_content_and_references() {
        let (text, stopped) = output(b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n");
        assert_eq!(stopped, None);
        assert_eq!(
            text,
            "obj 1 0\n Type: /Catalog\n Referencing: 2 0 R\n \n<</Type/Catalog/Pages 2 0 R>>\n\n\n  <<\n    /Type /Catalog\n    /Pages 2 0 R\n  >>\n\n \n<</Type/Catalog/Pages 2 0 R>>\n\n\n<</Type/Catalog/Pages 2 0 R>>\n\n\n"
        );
    }

    #[test]
    fn a_flate_stream_prints_as_python_bytes_and_a_bad_one_ends_the_run() {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"it's\n").expect("compresses");
        let compressed = encoder.finish().expect("compresses");
        let mut file = b"1 0 obj\n<</Filter/FlateDecode>>\nstream\n".to_vec();
        file.extend_from_slice(&compressed);
        file.extend_from_slice(b"\nendstream\nendobj\n");
        let run_ok = run(&file, &UNLIMITED);
        assert_eq!(run_ok.stopped, None);
        let found = String::from_utf8_lossy(&run_ok.stdout).into_owned();
        assert!(found.contains(" b\"it's\\n\"\n"), "{found}");

        let bad = b"1 0 obj\n<</Filter/FlateDecode>>\nstream\nnot zlib data\nendstream\nendobj\n";
        let run_bad = run(bad, &UNLIMITED);
        assert_eq!(run_bad.stopped, Some(Stop::Crash("AttributeError")));
        assert_eq!(run_bad.exit(), 1);
        assert!(run_bad.stderr());
    }

    #[test]
    fn a_number_at_the_end_of_a_file_crashes_as_the_script_does() {
        assert_eq!(output(b"1\n").1, Some(Stop::Crash("TypeError")));
        assert_eq!(output(b"1 0").1, Some(Stop::Crash("TypeError")));
        assert_eq!(output(b"/").1, Some(Stop::Crash("TypeError")));
        assert_eq!(
            output(b"12a 0 obj\nendobj").1,
            Some(Stop::Crash("ValueError"))
        );
        assert_eq!(
            output(b"not a pdf").0,
            "todo 10: 3 'not'\ntodo 10: 3 'a'\ntodo 10: 3 'pdf'\n"
        );
    }

    #[test]
    fn repr_follows_python() {
        assert_eq!(str_repr(b"a'b"), b"\"a'b\"");
        assert_eq!(str_repr(b"a'b\""), b"'a\\'b\"'");
        assert_eq!(
            str_repr(b"\x00\t\x7f\xa0\xa1\xad"),
            b"'\\x00\\t\\x7f\\xa0\xa1\\xad'"
        );
        assert_eq!(bytes_repr(b"\x00'\xff"), b"b\"\\x00'\\xff\"");
    }

    #[test]
    fn names_decode_as_python_int_does() {
        assert_eq!(canonicalize(b"/a#41b").as_ref(), b"/aAb");
        assert_eq!(canonicalize(b"/a#zzb").as_ref(), b"/a#zzb");
        // a '#' needs two characters after it
        assert_eq!(canonicalize(b"/a#41").as_ref(), b"/aA");
        assert_eq!(canonicalize(b"/a#4").as_ref(), b"/a#4");
        assert_eq!(canonicalize(b"/a#-1b").as_ref(), b"/a#-1b");
        assert_eq!(canonicalize(b"/a#+1b").as_ref(), b"/a\x01b");
    }

    #[test]
    fn integers_are_python_ints() {
        assert_eq!(py_int(b"007").expect("reads"), "7");
        assert_eq!(py_int(b"1_000").expect("reads"), "1000");
        assert!(py_int(b"1__0").is_err());
        assert!(py_int(b"1_").is_err());
        assert!(py_int(&vec![b'1'; INT_MAX_STR_DIGITS + 1]).is_err());
    }

    #[test]
    fn filters_decode_as_the_script_does() {
        assert_eq!(ascii_hex_decode(b"41 42>").expect("decodes"), b"AB");
        assert!(ascii_hex_decode(b"4").is_none());
        assert_eq!(ascii85_decode(b"87cUR~>").expect("decodes"), b"Hell");
        assert!(ascii85_decode(b"8z").is_none());
        assert!(
            matches!(run_length_decode(b"\x01ab\xfex\x80", 100), Lzw::Done(out) if out == b"abxxx")
        );
        assert!(matches!(run_length_decode(b"", 100), Lzw::Failed));
        // 256, 'A', 'B', 258 (AB), 257, in 9 bits
        let codes = [256u32, 65, 66, 258, 257];
        let mut bits = 0u64;
        let mut count = 0;
        for code in codes {
            bits = (bits << 9) | u64::from(code);
            count += 9;
        }
        bits <<= 64 - count;
        let bytes = bits.to_be_bytes();
        assert!(matches!(lzw_decode(&bytes[..6], 100), Lzw::Done(out) if out == b"ABAB"));
        // the first code must be a clear
        assert!(matches!(lzw_decode(&[0x20, 0x80, 0, 0], 100), Lzw::Failed));
    }

    #[test]
    fn limits_stop_a_run_with_what_it_has() {
        use std::io::Write;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&vec![0u8; 1 << 22]).expect("compresses");
        let bomb = encoder.finish().expect("compresses");
        let mut file = b"1 0 obj\n<</Filter/FlateDecode>>\nstream\n".to_vec();
        file.extend_from_slice(&bomb);
        file.extend_from_slice(b"\nendstream\nendobj\n");
        let limits = Limits {
            decoded_bytes: 1 << 20,
            ..UNLIMITED
        };
        let run = run(&file, &limits);
        assert_eq!(run.stopped, Some(Stop::Limit("decoded stream")));
        assert_eq!(run.exit(), 0);
        assert!(String::from_utf8_lossy(&run.stdout).contains("obj 1 0"));
    }
}
