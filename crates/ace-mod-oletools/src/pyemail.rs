//! `email.message_from_bytes` with open_mht's loosened `headerRE`, compat32, then what open_mht asks
//! of each part in `walk()`. A str from `message_from_bytes` holds ASCII and U+DC80-U+DCFF one to one
//! with the input bytes, so the parser works on the bytes themselves. Only the parameter values that
//! go through a codec need real code points.

use std::collections::HashMap;
use std::rc::Rc;

use ace_results::bytes::{Bytes, TextOrBytes};
use memchr::{memchr, memchr2};

use crate::codepage::Decoder;
use crate::py::{PyErr, PyResult, is_space, is_word, memory_error};

/// One message of `walk()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub content_type: String,
    pub filename: Option<TextOrBytes>,
    pub payload: Option<Vec<u8>>,
}

/// `walk()`, each part: `get_content_type()`, `get_filename(None)`, `get_payload(decode=True)`.
pub fn parts(data: &[u8]) -> PyResult<Vec<Part>> {
    match parts_until_error(data) {
        (parts, None) => Ok(parts),
        (_, Some(error)) => Err(error),
    }
}

/// What open_mht's loop gets through before an exception, and that exception. The parts it already
/// has were processed by the time Python raises.
pub fn parts_until_error(data: &[u8]) -> (Vec<Part>, Option<PyErr>) {
    let parser = match parse(data) {
        Ok(parser) => parser,
        Err(error) => return (Vec::new(), Some(error)),
    };
    let mut parts = Vec::with_capacity(parser.msgs.len());
    // messages are created in the order walk() visits them
    for msg in &parser.msgs {
        let filename = match get_filename(data, msg) {
            Ok(filename) => filename,
            Err(error) => return (parts, Some(error)),
        };
        parts.push(Part {
            content_type: content_type(data, msg),
            filename: filename.map(|chars| canon(&chars)),
            payload: get_payload(data, msg),
        });
    }
    (parts, None)
}

/// What a message of `walk()` gives a caller that wants only its type and its body:
/// `get_content_type()` and `get_payload(decode=True)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkedPart {
    pub content_type: String,
    pub payload: Option<Vec<u8>>,
}

/// How the feed parser is set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    /// The stock `headerRE`, `^(From |[\041-\071\073-\176]*:|[\t ])`, rather than open_mht's
    /// loosened one, which takes any printable first character but `:`.
    pub strict_headers: bool,
    /// Python frames under the root `_parsegen`, for where `RecursionError` comes.
    pub root_depth: usize,
}

/// open_mht's: `message_from_bytes` with its loosened `headerRE`.
pub const OPEN_MHT: Setup = Setup {
    strict_headers: false,
    root_depth: ROOT_DEPTH,
};

/// `email.parser.BytesFeedParser()` under compat32, fed `data` and closed, then `walk()`: each
/// message's content type and decoded payload, None for a multipart or a `message/*` one, whose
/// payload is a list. Python builds every message before the walk, so an exception while parsing
/// leaves nothing.
pub fn walk_payloads(data: &[u8], setup: Setup) -> PyResult<Vec<WalkedPart>> {
    let parser = parse_with(data, setup)?;
    Ok(parser
        .msgs
        .iter()
        .map(|msg| WalkedPart {
            content_type: content_type(data, msg),
            payload: get_payload(data, msg),
        })
        .collect())
}

fn recursion_error() -> PyErr {
    PyErr::new("RecursionError", "maximum recursion depth exceeded")
}

/// Python frames under the root `_parsegen`, with open_mht's own frame about 6 deep:
/// message_from_bytes, parsebytes, parsestr, parse, feed, _call_parse.
const ROOT_DEPTH: usize = 13;
const RECURSION_LIMIT: usize = 1000;

type Span = (u32, u32);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Kind {
    #[default]
    Other,
    Message,
    Multipart,
    DeliveryStatus,
}

/// A message, with the only headers ever looked at: `get` returns the first of a name.
#[derive(Debug, Default)]
struct Msg {
    content_type: Option<Span>,
    disposition: Option<Span>,
    encoding: Option<Span>,
    payload: Payload,
    has_headers: bool,
    in_digest: bool,
    is_list: bool,
    // what's needed of get_content_type while parsing, which a parent's every child asks for
    content_type_cost: u8,
    kind: Kind,
    is_digest: bool,
}

/// A payload is one run of the input, but for a `From ` line pushed back past the blank line that ended
/// the headers.
#[derive(Debug, Default, Clone, Copy)]
struct Payload {
    head: Span,
    body: Span,
}

impl Payload {
    fn append(&mut self, line: Span) {
        if is_empty(self.body) {
            self.body = line;
        } else if self.body.1 == line.0 {
            self.body.1 = line.1;
        } else {
            self.head = self.body;
            self.body = line;
        }
    }

    fn bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut out = slice(data, self.head).to_vec();
        out.extend_from_slice(slice(data, self.body));
        out
    }

    /// `NLCRE_eol`: drops one line end from the end.
    fn trim_line_end(&mut self, data: &[u8]) {
        let body = slice(data, self.body);
        if body.ends_with(b"\r\n") {
            self.body.1 -= 2;
        } else if body == b"\n" && slice(data, self.head).ends_with(b"\r") {
            self.body.1 -= 1;
            self.head.1 -= 1;
        } else if matches!(body.last(), Some(b'\r' | b'\n')) {
            self.body.1 -= 1;
        }
    }
}

fn slice(data: &[u8], span: Span) -> &[u8] {
    &data[span.0 as usize..span.1 as usize]
}

/// `str(msg.get(name))`: a value with surrogates comes back as a Header, whose str is U+FFFD for each.
fn header_str(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        out.push(if byte < 0x80 {
            byte as char
        } else {
            '\u{fffd}'
        });
    }
    out
}

fn content_type(data: &[u8], msg: &Msg) -> String {
    let Some(span) = msg.content_type else {
        return if msg.in_digest {
            "message/rfc822"
        } else {
            "text/plain"
        }
        .to_owned();
    };
    let value = header_str(slice(data, span));
    let main = value.split(';').next().unwrap_or("");
    let ctype = main.trim_matches(is_space).to_ascii_lowercase();
    if ctype.bytes().filter(|&byte| byte == b'/').count() != 1 {
        return "text/plain".to_owned();
    }
    ctype
}

enum Eof {
    NewLine,
    Boundary(Option<Rc<[u8]>>),
}

struct MultipartState {
    separator: Option<Rc<[u8]>>,
    capturing: bool,
    preamble: Payload,
    close_seen: bool,
}

enum Frame {
    Delivery,
    Message,
    Multipart(MultipartState),
}

enum Next {
    Call,
    Return,
}

struct Parser<'a> {
    data: &'a [u8],
    at: usize,
    // the deque's front, past the lines still in the input; can hold ''
    pushed: Vec<Span>,
    eof: Vec<Eof>,
    boundaries: usize,
    msgs: Vec<Msg>,
    open: Vec<usize>,
    cur: Option<usize>,
    last: usize,
    frames: Vec<Frame>,
    headers: Vec<Span>,
    setup: Setup,
}

fn parse(data: &[u8]) -> PyResult<Parser<'_>> {
    parse_with(data, OPEN_MHT)
}

/// `headerRE.match(line)` for the stock `headerRE`.
fn is_strict_header(line: &[u8]) -> bool {
    if line.starts_with(b"From ") || matches!(line[0], b'\t' | b' ') {
        return true;
    }
    for &byte in line {
        if byte == b':' {
            return true;
        }
        if !(0x21..=0x7e).contains(&byte) {
            return false;
        }
    }
    false
}

fn parse_with(data: &[u8], setup: Setup) -> PyResult<Parser<'_>> {
    if u32::try_from(data.len()).is_err() {
        return Err(memory_error());
    }
    let mut parser = Parser {
        data,
        at: 0,
        pushed: Vec::new(),
        eof: Vec::new(),
        boundaries: 0,
        msgs: Vec::new(),
        open: Vec::new(),
        cur: None,
        last: 0,
        frames: Vec::new(),
        headers: Vec::new(),
        setup,
    };
    let mut next = Next::Call;
    loop {
        next = match next {
            Next::Call => parser.begin()?,
            Next::Return => match parser.frames.pop() {
                None => break,
                Some(frame) => parser.resume(frame)?,
            },
        };
    }
    Ok(parser)
}

const EMPTY: Span = (0, 0);

fn is_empty(line: Span) -> bool {
    line.0 == line.1
}

fn boundary_match(data: &[u8], separator: Option<&[u8]>, line: Span) -> Option<bool> {
    let rest = slice(data, line).strip_prefix(separator?)?;
    let (end, rest) = match rest.strip_prefix(b"--") {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    let start = rest
        .iter()
        .position(|&byte| byte != b' ' && byte != b'\t')
        .unwrap_or(rest.len());
    match &rest[start..] {
        b"" | b"\n" | b"\r" | b"\r\n" => Some(end),
        _ => None,
    }
}

impl Parser<'_> {
    /// That a chain of `frames` Python calls from the `_parsegen` of this level fits.
    fn enter(&self, frames: usize) -> PyResult<()> {
        if self.setup.root_depth + self.frames.len() + frames > RECURSION_LIMIT {
            return Err(recursion_error());
        }
        Ok(())
    }

    fn next_line(&mut self) -> Span {
        if let Some(line) = self.pushed.pop() {
            return line;
        }
        let start = self.at;
        if start >= self.data.len() {
            return EMPTY;
        }
        let rest = &self.data[start..];
        let end = match memchr2(b'\n', b'\r', rest) {
            None => self.data.len(),
            Some(at) if rest[at] == b'\r' && rest.get(at + 1) == Some(&b'\n') => start + at + 2,
            Some(at) => start + at + 1,
        };
        self.at = end;
        (start as u32, end as u32)
    }

    /// `BufferedSubFile.readline`, `depth` frames down from this `_parsegen`.
    fn readline(&mut self, depth: usize) -> PyResult<Span> {
        self.enter(depth)?;
        let line = self.next_line();
        if is_empty(line) || self.eof.is_empty() {
            return Ok(line);
        }
        let first = self.data[line.0 as usize];
        if !matches!(first, b'-' | b'\r' | b'\n') {
            if self.boundaries > 0 {
                self.enter(depth + 1)?;
            }
            return Ok(line);
        }
        for at in (0..self.eof.len()).rev() {
            let matched = match &self.eof[at] {
                Eof::NewLine => matches!(first, b'\r' | b'\n'),
                Eof::Boundary(separator) => {
                    self.enter(depth + 1)?;
                    boundary_match(self.data, separator.as_deref(), line).is_some()
                }
            };
            if matched {
                self.pushed.push(line);
                return Ok(EMPTY);
            }
        }
        Ok(line)
    }

    fn cur_index(&self) -> usize {
        self.cur.unwrap_or(0)
    }

    fn cost_of(&self, index: usize) -> usize {
        usize::from(self.msgs[index].content_type_cost)
    }

    /// The start of `_parsegen`, up to its first recursion or its end.
    fn begin(&mut self) -> PyResult<Next> {
        self.enter(2)?;
        let mut msg = Msg {
            content_type_cost: 2,
            ..Msg::default()
        };
        if let Some(parent) = self.cur
            && self.msgs[parent].has_headers
        {
            self.enter(1 + self.cost_of(parent))?;
            msg.in_digest = self.msgs[parent].is_digest;
        }
        let index = self.msgs.len();
        if let Some(&parent) = self.open.last() {
            self.msgs[parent].is_list = true;
        }
        self.msgs.push(msg);
        self.open.push(index);
        self.cur = Some(index);
        self.last = index;

        let mut headers = std::mem::take(&mut self.headers);
        headers.clear();
        loop {
            let line = self.readline(2)?;
            if is_empty(line) {
                break;
            }
            let first = self.data[line.0 as usize];
            let is_header = if self.setup.strict_headers {
                is_strict_header(slice(self.data, line))
            } else {
                matches!(first, b'\t' | b' ') || (matches!(first, 0x21..=0x7e) && first != b':')
            };
            if !is_header {
                if !matches!(first, b'\r' | b'\n') {
                    self.enter(2)?;
                    self.pushed.push(line);
                }
                break;
            }
            headers.push(line);
        }
        let parsed = self.parse_headers(&headers);
        headers.clear();
        self.headers = headers;
        parsed?;
        self.classify(index);
        let cost = self.cost_of(index);

        self.enter(cost)?;
        let kind = self.msgs[index].kind;
        if kind == Kind::DeliveryStatus {
            self.eof.push(Eof::NewLine);
            self.frames.push(Frame::Delivery);
            return Ok(Next::Call);
        }
        self.enter(cost + 1)?;
        if kind == Kind::Message {
            self.frames.push(Frame::Message);
            return Ok(Next::Call);
        }
        if kind == Kind::Multipart {
            return self.begin_multipart(index);
        }
        let payload = self.read_rest()?;
        self.msgs[index].payload = payload;
        Ok(Next::Return)
    }

    fn classify(&mut self, index: usize) {
        let msg = &self.msgs[index];
        let cost = match msg.content_type {
            None => 2,
            Some(span) if slice(self.data, span).is_ascii() => 5,
            Some(_) => 6,
        };
        let ctype = content_type(self.data, msg);
        let kind = if ctype == "message/delivery-status" {
            Kind::DeliveryStatus
        } else {
            match ctype.split('/').next() {
                Some("message") => Kind::Message,
                Some("multipart") => Kind::Multipart,
                _ => Kind::Other,
            }
        };
        let msg = &mut self.msgs[index];
        msg.content_type_cost = cost;
        msg.kind = kind;
        msg.is_digest = ctype == "multipart/digest";
    }

    fn parse_headers(&mut self, lines: &[Span]) -> PyResult<()> {
        self.enter(1)?;
        let mut open: Option<Span> = None;
        for (number, &line) in lines.iter().enumerate() {
            let text = slice(self.data, line);
            if matches!(text[0], b' ' | b'\t') {
                if let Some(span) = &mut open {
                    span.1 = line.1;
                }
                continue;
            }
            if let Some(span) = open.take() {
                self.enter(2)?;
                self.set_raw(span);
            }
            if text.starts_with(b"From ") {
                if number == 0 {
                    continue;
                } else if number == lines.len() - 1 {
                    self.enter(2)?;
                    self.pushed.push(line);
                    return Ok(());
                }
                self.enter(2)?;
                continue;
            }
            match memchr(b':', text) {
                None => {
                    return Err(PyErr::new(
                        "AssertionError",
                        "_parse_headers fed line with no : and no leading WS",
                    ));
                }
                // InvalidHeaderDefect("Missing header name."), which only the stock headerRE
                // lets through
                Some(0) => {
                    self.enter(2)?;
                    continue;
                }
                Some(_) => open = Some(line),
            }
        }
        if let Some(span) = open {
            self.enter(2)?;
            self.set_raw(span);
        }
        Ok(())
    }

    /// `set_raw(*header_source_parse(lines))`, for the span of a header and its continuations.
    fn set_raw(&mut self, span: Span) {
        let text = slice(self.data, span);
        let colon = memchr(b':', text).unwrap_or(0);
        let name = &text[..colon];
        let mut start = span.0 as usize + colon + 1;
        let mut end = span.1 as usize;
        while start < end && matches!(self.data[start], b' ' | b'\t' | b'\r' | b'\n') {
            start += 1;
        }
        while start < end && matches!(self.data[end - 1], b'\r' | b'\n') {
            end -= 1;
        }
        let value = Some((start as u32, end as u32));
        let index = self.cur_index();
        let msg = &mut self.msgs[index];
        msg.has_headers = true;
        let slot = if name.eq_ignore_ascii_case(b"content-type") {
            &mut msg.content_type
        } else if name.eq_ignore_ascii_case(b"content-disposition") {
            &mut msg.disposition
        } else if name.eq_ignore_ascii_case(b"content-transfer-encoding") {
            &mut msg.encoding
        } else {
            return;
        };
        if slot.is_none() {
            *slot = value;
        }
    }

    /// `''.join(self._input)`, as a span.
    fn read_rest(&mut self) -> PyResult<Payload> {
        let mut whole = Payload::default();
        loop {
            let line = self.readline(2)?;
            if is_empty(line) {
                return Ok(whole);
            }
            whole.append(line);
        }
    }

    fn begin_multipart(&mut self, index: usize) -> PyResult<Next> {
        // get_boundary, get_param, _get_params_preserve, get, then the header's own chain
        let ascii = self.msgs[index]
            .content_type
            .is_none_or(|span| slice(self.data, span).is_ascii());
        self.enter(if ascii { 7 } else { 8 })?;
        let boundary = get_boundary(self.data, &self.msgs[index])?;
        let Some(boundary) = boundary else {
            let payload = self.read_rest()?;
            self.msgs[index].payload = payload;
            return Ok(Next::Return);
        };
        // a boundary with anything a line can't hold never matches
        let separator = boundary_bytes(&boundary).map(|bytes| {
            let mut separator = Vec::with_capacity(bytes.len() + 2);
            separator.extend_from_slice(b"--");
            separator.extend_from_slice(&bytes);
            Rc::<[u8]>::from(separator)
        });
        let state = MultipartState {
            separator,
            capturing: true,
            preamble: Payload::default(),
            close_seen: false,
        };
        self.multipart_loop(state)
    }

    fn multipart_loop(&mut self, mut state: MultipartState) -> PyResult<Next> {
        let data = self.data;
        loop {
            let line = self.readline(1)?;
            if is_empty(line) {
                break;
            }
            match boundary_match(data, state.separator.as_deref(), line) {
                Some(true) => {
                    state.close_seen = true;
                    break;
                }
                Some(false) => {
                    if state.capturing {
                        state.capturing = false;
                        self.pushed.push(line);
                        continue;
                    }
                    loop {
                        let line = self.readline(1)?;
                        if boundary_match(data, state.separator.as_deref(), line).is_none() {
                            self.pushed.push(line);
                            break;
                        }
                    }
                    self.eof.push(Eof::Boundary(state.separator.clone()));
                    self.boundaries += 1;
                    self.frames.push(Frame::Multipart(state));
                    return Ok(Next::Call);
                }
                None => {
                    if !state.capturing {
                        return Err(PyErr::new("AssertionError", ""));
                    }
                    state.preamble.append(line);
                }
            }
        }
        if state.capturing {
            let index = self.cur_index();
            self.msgs[index].payload = state.preamble;
            self.read_rest()?;
            return Ok(Next::Return);
        }
        if state.close_seen {
            self.read_rest()?;
        }
        Ok(Next::Return)
    }

    fn pop_message(&mut self) {
        self.open.pop();
        self.cur = self.open.last().copied();
    }

    /// The `_parsegen` of this level, after the one it recursed into returned.
    fn resume(&mut self, frame: Frame) -> PyResult<Next> {
        match frame {
            Frame::Message => {
                self.pop_message();
                Ok(Next::Return)
            }
            Frame::Delivery => {
                self.pop_message();
                self.eof.pop();
                self.readline(1)?;
                let line = self.readline(1)?;
                if is_empty(line) {
                    return Ok(Next::Return);
                }
                self.pushed.push(line);
                self.eof.push(Eof::NewLine);
                self.frames.push(Frame::Delivery);
                Ok(Next::Call)
            }
            Frame::Multipart(state) => {
                let last = self.last;
                self.enter(1 + self.cost_of(last))?;
                let msg = &mut self.msgs[last];
                if msg.kind != Kind::Multipart && !msg.is_list {
                    // the newline before a boundary belongs to the boundary
                    msg.payload.trim_line_end(self.data);
                }
                self.eof.pop();
                self.boundaries -= 1;
                self.pop_message();
                self.last = self.cur_index();
                self.multipart_loop(state)
            }
        }
    }
}

// -- parameters

#[derive(Debug, Clone)]
enum Param {
    Plain(String),
    Extended(Option<String>, String),
}

fn find(text: &[u8], byte: u8, from: i64) -> i64 {
    let from = from.max(0) as usize;
    if from > text.len() {
        return -1;
    }
    memchr(byte, &text[from..]).map_or(-1, |at| (from + at) as i64)
}

/// `_parseparam`, with its odd walk over quotes kept.
fn parse_param_list(value: &str) -> Vec<String> {
    let mut joined = String::with_capacity(value.len() + 1);
    joined.push(';');
    joined.push_str(value);
    let text = joined.as_bytes();
    let count = |from: i64, end: i64| -> i64 {
        if from < 0 || from >= end {
            return 0;
        }
        let range = &text[from as usize..end as usize];
        let quotes = memchr::memchr_iter(b'"', range).count() as i64;
        let escaped = memchr::memchr_iter(b'"', range)
            .filter(|&at| at > 0 && range[at - 1] == b'\\')
            .count() as i64;
        quotes - escaped
    };
    let mut plist = Vec::new();
    let mut start: i64 = 0;
    while find(text, b';', start) == start {
        start += 1;
        let mut end = find(text, b';', start);
        let (mut ind, mut diff) = (start, 0i64);
        while end > 0 {
            diff += count(ind, end);
            if diff.rem_euclid(2) == 0 {
                break;
            }
            (end, ind) = (ind, find(text, b';', end + 1));
        }
        if end < 0 {
            end = text.len() as i64;
        }
        let (from, to) = (start as usize, end as usize);
        let piece = &joined[from..to];
        let f = match memchr(b'=', piece.as_bytes()) {
            None => piece.to_owned(),
            Some(i) => {
                let name = piece[..i].trim_end_matches(is_space).to_ascii_lowercase();
                format!("{name}={}", piece[i + 1..].trim_start_matches(is_space))
            }
        };
        plist.push(f.trim_matches(is_space).to_owned());
        start = end;
    }
    plist
}

fn unquote(text: &str) -> String {
    if text.len() > 1 {
        if text.starts_with('"') && text.ends_with('"') {
            return text[1..text.len() - 1]
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
        }
        if text.starts_with('<') && text.ends_with('>') {
            return text[1..text.len() - 1].to_owned();
        }
    }
    text.to_owned()
}

fn quote(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `urllib.parse.unquote(s, encoding="latin-1")`.
fn percent_decode_latin1(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |at: usize| bytes.get(at).and_then(|&b| (b as char).to_digit(16));
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut at = 0;
    while let Some(found) = memchr(b'%', &bytes[at..]) {
        at += found;
        if let (Some(high), Some(low)) = (hex(at + 1), hex(at + 2)) {
            out.push_str(&text[copied..at]);
            out.push(char::from_u32(high * 16 + low).unwrap_or('\u{fffd}'));
            at += 3;
            copied = at;
        } else {
            at += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// `rfc2231_continuation`: the name and the digits of a matching parameter name.
fn split_continuation(name: &str) -> Option<(&str, Option<&str>)> {
    let bytes = name.as_bytes();
    let star = bytes
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || b == b'_'))?;
    if star == 0 || bytes[star] != b'*' {
        return None;
    }
    let rest = &name[star + 1..];
    if rest.is_empty() {
        return Some((&name[..star], None));
    }
    let digits = rest.strip_suffix('*').unwrap_or(rest);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&name[..star], Some(digits)))
}

struct Continuation {
    // the number without its leading zeros; None when the name had none
    number: Option<String>,
    value: String,
    encoded: bool,
}

/// `utils.decode_params`.
fn decode_params(params: Vec<(String, String)>) -> PyResult<Vec<(String, Param)>> {
    let mut out = Vec::with_capacity(params.len());
    let mut names: HashMap<String, usize> = HashMap::new();
    let mut continued: Vec<(String, Vec<Continuation>)> = Vec::new();
    let mut params = params.into_iter();
    if let Some((name, value)) = params.next() {
        out.push((name, Param::Plain(value)));
    }
    for (name, value) in params {
        let encoded = name.ends_with('*');
        let value = unquote(&value);
        let Some((base, digits)) = split_continuation(&name) else {
            out.push((name, Param::Plain(format!("\"{}\"", quote(&value)))));
            continue;
        };
        let number = match digits {
            None => None,
            Some(digits) if digits.len() > 4300 => {
                return Err(PyErr::new(
                    "ValueError",
                    format!(
                        "Exceeds the limit (4300 digits) for integer string conversion: value has \
                         {} digits; use sys.set_int_max_str_digits() to increase the limit",
                        digits.len()
                    ),
                ));
            }
            Some(digits) => Some(digits.trim_start_matches('0').to_owned()),
        };
        let at = *names.entry(base.to_owned()).or_insert_with(|| {
            continued.push((base.to_owned(), Vec::new()));
            continued.len() - 1
        });
        continued[at].1.push(Continuation {
            number,
            value,
            encoded,
        });
    }
    for (name, mut pieces) in continued {
        if pieces
            .iter()
            .any(|piece| piece.number.as_deref() == Some(""))
        {
            pieces.retain(|piece| piece.number.is_some());
        }
        let key = |piece: &Continuation| {
            let number = piece.number.clone().unwrap_or_default();
            (number.len(), number)
        };
        pieces.sort_by_key(key);
        let mut extended = false;
        let mut value = String::new();
        for piece in &pieces {
            if piece.encoded {
                value.push_str(&percent_decode_latin1(&piece.value));
                extended = true;
            } else {
                value.push_str(&piece.value);
            }
        }
        let value = quote(&value);
        if extended {
            let mut split = value.splitn(3, '\'');
            let (first, second, third) = (split.next(), split.next(), split.next());
            match (first, second, third) {
                (Some(charset), Some(_), Some(text)) => {
                    let text = format!("\"{text}\"");
                    out.push((name, Param::Extended(Some(charset.to_owned()), text)));
                }
                _ => out.push((name, Param::Extended(None, format!("\"{value}\"")))),
            }
        } else {
            out.push((name, Param::Plain(format!("\"{value}\""))));
        }
    }
    Ok(out)
}

/// `get_param(param, header=...)`, with its unquote.
fn get_param(data: &[u8], header: Option<Span>, param: &str) -> PyResult<Option<Param>> {
    let Some(span) = header else {
        return Ok(None);
    };
    let value = header_str(slice(data, span));
    let params = parse_param_list(&value)
        .into_iter()
        .map(|p| match p.split_once('=') {
            Some((name, value)) => (
                name.trim_matches(is_space).to_owned(),
                value.trim_matches(is_space).to_owned(),
            ),
            None => (p.trim_matches(is_space).to_owned(), String::new()),
        })
        .collect();
    for (name, value) in decode_params(params)? {
        if name.eq_ignore_ascii_case(param) {
            return Ok(Some(match value {
                Param::Plain(text) => Param::Plain(unquote(&text)),
                Param::Extended(charset, text) => Param::Extended(charset, unquote(&text)),
            }));
        }
    }
    Ok(None)
}

fn to_chars(text: &str) -> Vec<u32> {
    text.chars().map(u32::from).collect()
}

/// `utils.collapse_rfc2231_value`.
fn collapse(value: Param) -> PyResult<Vec<u32>> {
    let (charset, text) = match value {
        Param::Plain(text) => return Ok(to_chars(&unquote(&text))),
        Param::Extended(charset, text) => (charset, text),
    };
    let mut raw = Vec::with_capacity(text.len());
    for c in text.chars() {
        let code = u32::from(c);
        if code <= 0xff {
            raw.push(code as u8);
        } else if code <= 0xffff {
            raw.extend_from_slice(format!("\\u{code:04x}").as_bytes());
        } else {
            raw.extend_from_slice(format!("\\U{code:08x}").as_bytes());
        }
    }
    let charset = charset.as_deref().unwrap_or("us-ascii");
    Ok(match decode_codec(charset, &raw)? {
        Some(chars) => chars,
        None => to_chars(&unquote(&text)),
    })
}

fn is_space_code(code: u32) -> bool {
    char::from_u32(code).is_some_and(is_space)
}

fn get_filename(data: &[u8], msg: &Msg) -> PyResult<Option<Vec<u32>>> {
    let mut value = get_param(data, msg.disposition, "filename")?;
    if value.is_none() {
        value = get_param(data, msg.content_type, "name")?;
    }
    let Some(value) = value else {
        return Ok(None);
    };
    let chars = collapse(value)?;
    let start = chars
        .iter()
        .position(|&c| !is_space_code(c))
        .unwrap_or(chars.len());
    let end = chars
        .iter()
        .rposition(|&c| !is_space_code(c))
        .map_or(start, |at| at + 1);
    Ok(Some(chars[start..end].to_vec()))
}

fn get_boundary(data: &[u8], msg: &Msg) -> PyResult<Option<Vec<u32>>> {
    let Some(value) = get_param(data, msg.content_type, "boundary")? else {
        return Ok(None);
    };
    let mut chars = collapse(value)?;
    while chars.last().is_some_and(|&c| is_space_code(c)) {
        chars.pop();
    }
    Ok(Some(chars))
}

fn boundary_bytes(chars: &[u32]) -> Option<Vec<u8>> {
    chars
        .iter()
        .map(|&c| match c {
            0..=0x7f => Some(c as u8),
            0xdc80..=0xdcff => Some((c - 0xdc00) as u8),
            _ => None,
        })
        .collect()
}

/// side.py's `canon` of a str.
fn canon(chars: &[u32]) -> TextOrBytes {
    let surrogate = |c: u32| (0xd800..=0xdfff).contains(&c);
    if !chars.iter().any(|&c| surrogate(c)) {
        return TextOrBytes::Text(chars.iter().filter_map(|&c| char::from_u32(c)).collect());
    }
    let escaped = chars
        .iter()
        .all(|&c| !surrogate(c) || (0xdc80..=0xdcff).contains(&c));
    let mut out = Vec::with_capacity(chars.len());
    for &c in chars {
        if let Some(c) = char::from_u32(c) {
            let mut buffer = [0; 4];
            out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
        } else if escaped {
            out.push((c - 0xdc00) as u8);
        } else {
            out.extend_from_slice(&[
                0xe0 | (c >> 12) as u8,
                0x80 | ((c >> 6) & 0x3f) as u8,
                0x80 | (c & 0x3f) as u8,
            ]);
        }
    }
    TextOrBytes::Bytes(Bytes(out))
}

// -- get_payload

fn get_payload(data: &[u8], msg: &Msg) -> Option<Vec<u8>> {
    if msg.is_list {
        return None;
    }
    let payload = msg.payload.bytes(data);
    let Some(span) = msg.encoding else {
        return Some(payload);
    };
    let cte = header_str(slice(data, span));
    let cte = cte.trim_matches(is_space).to_ascii_lowercase();
    Some(match cte.as_str() {
        "quoted-printable" => a2b_qp(&payload),
        "base64" => decode_b(&payload),
        "x-uuencode" | "uuencode" | "uue" | "x-uue" => decode_uu(&payload).unwrap_or(payload),
        _ => payload,
    })
}

fn a2b_qp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0;
    while at < data.len() {
        if data[at] != b'=' {
            out.push(data[at]);
            at += 1;
            continue;
        }
        at += 1;
        if at >= data.len() {
            break;
        }
        match data[at] {
            b'\n' => at += 1,
            b'\r' => {
                at += memchr(b'\n', &data[at..]).unwrap_or(data.len() - at);
                if at < data.len() {
                    at += 1;
                }
            }
            b'=' => {
                out.push(b'=');
                at += 1;
            }
            first => {
                let digits = data.get(at + 1).and_then(|&second| {
                    Some((
                        char::from(first).to_digit(16)?,
                        char::from(second).to_digit(16)?,
                    ))
                });
                if let Some((high, low)) = digits {
                    out.push((high * 16 + low) as u8);
                    at += 2;
                } else {
                    out.push(b'=');
                }
            }
        }
    }
    out
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `binascii.a2b_base64`. None is `binascii.Error`.
fn a2b_base64(data: &[u8], extra_padding: &[u8], strict: bool) -> Option<Vec<u8>> {
    let total = data.len() + extra_padding.len();
    let mut out = Vec::with_capacity(total.div_ceil(4) * 3);
    let (mut quad, mut left, mut pads) = (0, 0u8, 0);
    for &byte in data.iter().chain(extra_padding) {
        if byte == b'=' {
            pads += 1;
            if (quad >= 2 && quad + pads <= 4) || !strict {
                continue;
            }
            return None;
        }
        let Some(value) = base64_value(byte) else {
            if strict {
                return None;
            }
            continue;
        };
        if pads > 0 && strict {
            return None;
        }
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = value;
            }
            1 => {
                quad = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    if quad == 1 || (quad != 0 && quad + pads < 4) {
        None
    } else {
        Some(out)
    }
}

/// `_encoded_words.decode_b(b''.join(payload.splitlines()))`.
fn decode_b(payload: &[u8]) -> Vec<u8> {
    let encoded: Vec<u8> = payload
        .iter()
        .copied()
        .filter(|&byte| byte != b'\n' && byte != b'\r')
        .collect();
    let padding: &[u8] = match encoded.len() % 4 {
        1 => b"===",
        2 => b"==",
        3 => b"=",
        _ => b"",
    };
    a2b_base64(&encoded, padding, true)
        .or_else(|| a2b_base64(&encoded, b"", false))
        .or_else(|| a2b_base64(&encoded, b"==", false))
        .unwrap_or(encoded)
}

/// `bytes.splitlines()`.
fn split_lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut at = 0;
    std::iter::from_fn(move || {
        if at >= data.len() {
            return None;
        }
        let rest = &data[at..];
        let Some(end) = memchr2(b'\n', b'\r', rest) else {
            at = data.len();
            return Some(rest);
        };
        at += end
            + if rest[end] == b'\r' && rest.get(end + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
        Some(&rest[..end])
    })
}

/// `int(text, base=8)` not raising ValueError.
fn is_octal_int(text: &[u8]) -> bool {
    let is_c_space = |b: &u8| matches!(*b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let start = text
        .iter()
        .position(|b| !is_c_space(b))
        .unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|b| !is_c_space(b))
        .map_or(start, |at| at + 1);
    let mut digits = &text[start..end];
    if let [b'+' | b'-', rest @ ..] = digits {
        digits = rest;
    }
    if let [b'0', b'o' | b'O', rest @ ..] = digits {
        digits = rest.strip_prefix(b"_").unwrap_or(rest);
    }
    if digits.is_empty() || digits[0] == b'_' || digits[digits.len() - 1] == b'_' {
        return false;
    }
    let mut previous = 0;
    for &byte in digits {
        if !(matches!(byte, b'0'..=b'7') || (byte == b'_' && previous != b'_')) {
            return false;
        }
        previous = byte;
    }
    true
}

fn a2b_uu(line: &[u8]) -> Option<Vec<u8>> {
    let mut remaining = usize::from(line[0].wrapping_sub(b' ') & 0o77);
    let mut out = Vec::with_capacity(remaining);
    let body = &line[1..];
    let mut at = 0;
    let (mut left, mut bits) = (0u32, 0);
    while remaining > 0 {
        let value = match body.get(at) {
            None | Some(b'\n' | b'\r') => 0,
            Some(&byte) => {
                if !(b' '..=b' ' + 64).contains(&byte) {
                    return None;
                }
                (byte - b' ') & 0o77
            }
        };
        at += 1;
        left = (left << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((left >> bits) & 0xff) as u8);
            left &= (1 << bits) - 1;
            remaining -= 1;
        }
    }
    let rest = body.get(at..).unwrap_or(&[]);
    if rest
        .iter()
        .any(|&byte| !matches!(byte, b' ' | 0x60 | b'\n' | b'\r'))
    {
        return None;
    }
    Some(out)
}

/// `_decode_uu`. None is its ValueError, with `binascii.Error` among them.
fn decode_uu(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut lines = split_lines(encoded);
    loop {
        let line = lines.next()?;
        if let Some(rest) = line.strip_prefix(b"begin ") {
            let mode = rest.split(|&byte| byte == b' ').next().unwrap_or(rest);
            if is_octal_int(mode) {
                break;
            }
        }
    }
    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() {
            return None;
        }
        let is_space = |byte: &u8| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n' | 0x0c);
        let start = line.iter().position(|b| !is_space(b)).unwrap_or(line.len());
        let end = line
            .iter()
            .rposition(|b| !is_space(b))
            .map_or(start, |at| at + 1);
        if &line[start..end] == b"end" {
            break;
        }
        let decoded = a2b_uu(line).or_else(|| {
            let count = ((usize::from(line[0].wrapping_sub(32)) & 63) * 4 + 5) / 3;
            a2b_uu(&line[..count.min(line.len())])
        })?;
        out.extend_from_slice(&decoded);
    }
    Some(out)
}

// -- codecs: str(bytes, name, 'replace')

#[derive(Clone, Copy)]
enum Codec {
    Ascii,
    Latin1,
    Utf8,
    Utf8Sig,
    Utf7,
    Utf16(i8),
    Utf32(i8),
    RawUnicodeEscape,
    UnicodeEscape,
    Idna,
    Punycode,
    Undefined,
    Page(u16),
    Single(&'static str),
    Approx(&'static encoding_rs::Encoding),
}

/// Python's name lookup: None is LookupError, which is what a non-text codec raises too.
fn find_codec(name: &str) -> Option<Codec> {
    let lower = name.to_ascii_lowercase();
    let mut norm = String::with_capacity(lower.len());
    let mut punct = false;
    for c in lower.chars() {
        if (is_word(c) && c != '_') || c == '.' {
            if punct && !norm.is_empty() {
                norm.push('_');
            }
            if c.is_ascii() {
                norm.push(c);
            }
            punct = false;
        } else {
            punct = true;
        }
    }
    let alias = |key: &str| {
        ALIASES
            .binary_search_by_key(&key, |row| row.0)
            .ok()
            .map(|at| ALIASES[at].1)
    };
    let module = match alias(&norm).or_else(|| alias(&norm.replace('.', "_"))) {
        Some(module) => module,
        None if norm.contains('.') => return None,
        None => norm.as_str(),
    };
    CODECS
        .binary_search_by_key(&module, |row| row.0)
        .ok()
        .map(|at| CODECS[at].1)
}

fn decode_codec(name: &str, raw: &[u8]) -> PyResult<Option<Vec<u32>>> {
    if name.contains('\0') {
        return Err(PyErr::new("ValueError", "embedded null character"));
    }
    // str(b'', ...) doesn't look the codec up
    if raw.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let Some(codec) = find_codec(name) else {
        return Ok(None);
    };
    const REPLACEMENT: u32 = 0xfffd;
    Ok(Some(match codec {
        Codec::Ascii => raw
            .iter()
            .map(|&b| if b < 0x80 { u32::from(b) } else { REPLACEMENT })
            .collect(),
        Codec::Latin1 => raw.iter().map(|&b| u32::from(b)).collect(),
        Codec::Utf8 => to_chars(&String::from_utf8_lossy(raw)),
        Codec::Utf8Sig => to_chars(&String::from_utf8_lossy(
            raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw),
        )),
        Codec::Utf7 => decode_utf7(raw),
        Codec::Utf16(order) => decode_utf16(raw, order),
        Codec::Utf32(order) => decode_utf32(raw, order),
        Codec::RawUnicodeEscape => decode_raw_unicode_escape(raw),
        Codec::UnicodeEscape => ace_pycompat::escape::decode_unicode_escape(raw),
        Codec::Idna => {
            return Err(PyErr::new(
                "UnicodeError",
                "Unsupported error handling: replace",
            ));
        }
        Codec::Punycode => decode_punycode(raw)?,
        Codec::Undefined => return Err(PyErr::new("UnicodeError", "undefined encoding")),
        Codec::Page(page) => to_chars(&Decoder::for_codepage(page).decode(raw)),
        Codec::Single(high) => {
            let table: Vec<char> = high.chars().collect();
            raw.iter()
                .map(|&b| {
                    if b < 0x80 {
                        u32::from(b)
                    } else {
                        u32::from(table[usize::from(b) - 0x80])
                    }
                })
                .collect()
        }
        Codec::Approx(encoding) => to_chars(&encoding.decode_without_bom_handling(raw).0),
    }))
}

fn decode_utf16(raw: &[u8], order: i8) -> Vec<u32> {
    let mut big = order > 0;
    let mut at = 0;
    if order == 0 && raw.len() >= 2 {
        match (raw[0], raw[1]) {
            (0xff, 0xfe) => at = 2,
            (0xfe, 0xff) => {
                big = true;
                at = 2;
            }
            _ => {}
        }
    }
    let unit = |at: usize| {
        let pair = [raw[at], raw[at + 1]];
        u32::from(if big {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        })
    };
    let mut out = Vec::with_capacity(raw.len() / 2 + 1);
    while at + 1 < raw.len() {
        let first = unit(at);
        at += 2;
        if !(0xd800..=0xdfff).contains(&first) {
            out.push(first);
        } else if first >= 0xdc00 {
            out.push(0xfffd);
        } else if at + 1 >= raw.len() {
            out.push(0xfffd);
            return out;
        } else {
            let second = unit(at);
            if (0xdc00..=0xdfff).contains(&second) {
                at += 2;
                out.push(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00));
            } else {
                out.push(0xfffd);
            }
        }
    }
    if at < raw.len() {
        out.push(0xfffd);
    }
    out
}

fn decode_utf32(raw: &[u8], order: i8) -> Vec<u32> {
    let mut big = order > 0;
    let mut at = 0;
    if order == 0 && raw.len() >= 4 {
        if raw[..4] == [0xff, 0xfe, 0, 0] {
            at = 4;
        } else if raw[..4] == [0, 0, 0xfe, 0xff] {
            big = true;
            at = 4;
        }
    }
    let mut out = Vec::with_capacity(raw.len() / 4 + 1);
    for four in raw[at..].chunks(4) {
        let code = <[u8; 4]>::try_from(four).map(|four| {
            if big {
                u32::from_be_bytes(four)
            } else {
                u32::from_le_bytes(four)
            }
        });
        out.push(match code {
            Ok(code) if code <= 0x10ffff && !(0xd800..=0xdfff).contains(&code) => code,
            _ => 0xfffd,
        });
    }
    out
}

/// `PyUnicode_DecodeUTF7Stateful` with 'replace', which can keep a lone surrogate.
fn decode_utf7(raw: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(raw.len());
    let mut in_shift = false;
    let (mut buffer, mut bits, mut surrogate) = (0u64, 0u32, 0u32);
    let mut at = 0;
    while at < raw.len() {
        let byte = raw[at];
        if !in_shift {
            at += 1;
            if byte != b'+' {
                out.push(if byte <= 127 { u32::from(byte) } else { 0xfffd });
            } else if raw.get(at) == Some(&b'-') {
                at += 1;
                out.push(u32::from(b'+'));
            } else if raw
                .get(at)
                .is_some_and(|&next| base64_value(next).is_none())
            {
                at += 1;
                out.push(0xfffd);
            } else {
                in_shift = true;
                (buffer, bits, surrogate) = (0, 0, 0);
            }
        } else if let Some(value) = base64_value(byte) {
            buffer = (buffer << 6) | u64::from(value);
            bits += 6;
            at += 1;
            if bits >= 16 {
                let unit = (buffer >> (bits - 16)) as u32;
                bits -= 16;
                buffer &= (1u64 << bits) - 1;
                if surrogate != 0 {
                    if (0xdc00..=0xdfff).contains(&unit) {
                        out.push(0x10000 + ((surrogate - 0xd800) << 10) + (unit - 0xdc00));
                        surrogate = 0;
                        continue;
                    }
                    out.push(surrogate);
                    surrogate = 0;
                }
                if (0xd800..=0xdbff).contains(&unit) {
                    surrogate = unit;
                } else {
                    out.push(unit);
                }
            }
        } else {
            in_shift = false;
            if bits >= 6 || (bits > 0 && buffer != 0) {
                at += 1;
                out.push(0xfffd);
                continue;
            }
            if surrogate != 0 && byte <= 127 && byte != b'+' {
                out.push(surrogate);
            }
            surrogate = 0;
            if byte == b'-' {
                at += 1;
            }
        }
    }
    if in_shift && (surrogate != 0 || bits >= 6 || (bits > 0 && buffer != 0)) {
        out.push(0xfffd);
    }
    out
}

fn decode_raw_unicode_escape(raw: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        let byte = raw[at];
        at += 1;
        if byte != b'\\' || at >= raw.len() {
            out.push(u32::from(byte));
            continue;
        }
        let next = raw[at];
        at += 1;
        let count = match next {
            b'u' => 4,
            b'U' => 8,
            _ => {
                out.push(u32::from(b'\\'));
                out.push(u32::from(next));
                continue;
            }
        };
        out.push(ace_pycompat::escape::hex_escape(raw, &mut at, count).unwrap_or(0xfffd));
    }
    out
}

// Each insertion moves what follows it, as in Python; a name past this is only a way to burn time.
const MAX_PUNYCODE: usize = 256 * 1024;

/// `encodings.punycode` with 'replace'. Its big integers saturate at 2**120 here.
fn decode_punycode(raw: &[u8]) -> PyResult<Vec<u32>> {
    if raw.len() > MAX_PUNYCODE {
        return Err(memory_error());
    }
    fn adapt(delta: u128, first: bool, count: u128) -> u128 {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / count;
        let mut divisions = 0;
        while delta > 455 {
            delta /= 35;
            divisions += 36;
        }
        divisions + 36 * delta / (delta + 38)
    }
    let (mut base, extended): (Vec<u32>, &[u8]) = match raw.iter().rposition(|&b| b == b'-') {
        None => (Vec::new(), raw),
        Some(at) => (
            raw[..at]
                .iter()
                .map(|&b| if b < 0x80 { u32::from(b) } else { 0xfffd })
                .collect(),
            &raw[at + 1..],
        ),
    };
    const LIMIT: u128 = 1 << 120;
    let (mut code, mut pos, mut bias, mut at) = (0x80u128, -1i128, 72u128, 0);
    while at < extended.len() {
        let start = at;
        let (mut delta, mut w, mut j) = (0u128, 1u128, 0u128);
        loop {
            let Some(&byte) = extended.get(at) else {
                return Ok(base);
            };
            at += 1;
            let digit = match byte.to_ascii_uppercase() {
                c @ b'A'..=b'Z' => u128::from(c - b'A'),
                c @ b'0'..=b'9' => u128::from(c) - 22,
                _ => return Ok(base),
            };
            let t = (36 * (j + 1)).saturating_sub(bias).clamp(1, 26);
            delta = delta.saturating_add(digit.saturating_mul(w)).min(LIMIT);
            if digit < t {
                break;
            }
            w = w.saturating_mul(36 - t).min(LIMIT);
            j += 1;
        }
        pos += delta as i128 + 1;
        let size = (base.len() + 1) as i128;
        code = code.saturating_add(pos.div_euclid(size) as u128);
        if code > 0x10ffff {
            code = u128::from(b'?');
        }
        pos = pos.rem_euclid(size);
        base.insert(pos as usize, code as u32);
        bias = adapt(delta, start == 0, base.len() as u128);
    }
    Ok(base)
}

/// `encodings`: the text codecs, by module.
static CODECS: &[(&str, Codec)] = &[
    ("ascii", Codec::Ascii),
    ("big5", Codec::Page(10002)),
    ("big5hkscs", Codec::Approx(&encoding_rs::BIG5_INIT)),
    ("charmap", Codec::Latin1),
    ("cp037", Codec::Page(37)),
    ("cp1006", Codec::Page(1006)),
    ("cp1026", Codec::Page(1026)),
    ("cp1125", Codec::Page(1125)),
    ("cp1140", Codec::Page(1140)),
    ("cp1250", Codec::Page(1250)),
    ("cp1251", Codec::Page(1251)),
    ("cp1252", Codec::Page(1252)),
    ("cp1253", Codec::Page(1253)),
    ("cp1254", Codec::Page(1254)),
    ("cp1255", Codec::Page(1255)),
    ("cp1256", Codec::Page(1256)),
    ("cp1257", Codec::Page(1257)),
    ("cp1258", Codec::Page(1258)),
    ("cp273", Codec::Page(273)),
    ("cp424", Codec::Page(424)),
    ("cp437", Codec::Page(437)),
    ("cp500", Codec::Page(500)),
    ("cp720", Codec::Page(720)),
    ("cp737", Codec::Page(737)),
    ("cp775", Codec::Page(775)),
    ("cp850", Codec::Page(850)),
    ("cp852", Codec::Page(852)),
    ("cp855", Codec::Page(855)),
    ("cp856", Codec::Page(856)),
    ("cp857", Codec::Page(857)),
    ("cp858", Codec::Page(858)),
    ("cp860", Codec::Page(860)),
    ("cp861", Codec::Page(861)),
    ("cp862", Codec::Page(862)),
    ("cp863", Codec::Page(863)),
    ("cp864", Codec::Page(864)),
    ("cp865", Codec::Page(865)),
    ("cp866", Codec::Page(866)),
    ("cp869", Codec::Page(869)),
    ("cp874", Codec::Page(874)),
    ("cp875", Codec::Page(875)),
    ("cp932", Codec::Page(932)),
    ("cp949", Codec::Page(949)),
    ("cp950", Codec::Page(950)),
    ("euc_jis_2004", Codec::Approx(&encoding_rs::EUC_JP_INIT)),
    ("euc_jisx0213", Codec::Approx(&encoding_rs::EUC_JP_INIT)),
    ("euc_jp", Codec::Approx(&encoding_rs::EUC_JP_INIT)),
    ("euc_kr", Codec::Approx(&encoding_rs::EUC_KR_INIT)),
    ("gb18030", Codec::Approx(&encoding_rs::GB18030_INIT)),
    ("gb2312", Codec::Page(10008)),
    ("gbk", Codec::Page(936)),
    ("hp_roman8", Codec::Page(1051)),
    ("hz", Codec::Ascii),
    ("idna", Codec::Idna),
    ("iso2022_jp", Codec::Approx(&encoding_rs::ISO_2022_JP_INIT)),
    (
        "iso2022_jp_1",
        Codec::Approx(&encoding_rs::ISO_2022_JP_INIT),
    ),
    (
        "iso2022_jp_2",
        Codec::Approx(&encoding_rs::ISO_2022_JP_INIT),
    ),
    (
        "iso2022_jp_2004",
        Codec::Approx(&encoding_rs::ISO_2022_JP_INIT),
    ),
    (
        "iso2022_jp_3",
        Codec::Approx(&encoding_rs::ISO_2022_JP_INIT),
    ),
    (
        "iso2022_jp_ext",
        Codec::Approx(&encoding_rs::ISO_2022_JP_INIT),
    ),
    ("iso2022_kr", Codec::Ascii),
    ("iso8859_1", Codec::Latin1),
    (
        "iso8859_10",
        Codec::Single(
            "\u{80}\u{81}\u{82}\u{83}\u{84}\u{85}\u{86}\u{87}\u{88}\u{89}\u{8a}\u{8b}\u{8c}\u{8d}\u{8e}\u{8f}\u{90}\u{91}\u{92}\u{93}\u{94}\u{95}\u{96}\u{97}\u{98}\u{99}\u{9a}\u{9b}\u{9c}\u{9d}\u{9e}\u{9f}\u{a0}\u{0104}\u{0112}\u{0122}\u{012a}\u{0128}\u{0136}\u{a7}\u{013b}\u{0110}\u{0160}\u{0166}\u{017d}\u{ad}\u{016a}\u{014a}\u{b0}\u{0105}\u{0113}\u{0123}\u{012b}\u{0129}\u{0137}\u{b7}\u{013c}\u{0111}\u{0161}\u{0167}\u{017e}\u{2015}\u{016b}\u{014b}\u{0100}\u{c1}\u{c2}\u{c3}\u{c4}\u{c5}\u{c6}\u{012e}\u{010c}\u{c9}\u{0118}\u{cb}\u{0116}\u{cd}\u{ce}\u{cf}\u{d0}\u{0145}\u{014c}\u{d3}\u{d4}\u{d5}\u{d6}\u{0168}\u{d8}\u{0172}\u{da}\u{db}\u{dc}\u{dd}\u{de}\u{df}\u{0101}\u{e1}\u{e2}\u{e3}\u{e4}\u{e5}\u{e6}\u{012f}\u{010d}\u{e9}\u{0119}\u{eb}\u{0117}\u{ed}\u{ee}\u{ef}\u{f0}\u{0146}\u{014d}\u{f3}\u{f4}\u{f5}\u{f6}\u{0169}\u{f8}\u{0173}\u{fa}\u{fb}\u{fc}\u{fd}\u{fe}\u{0138}",
        ),
    ),
    ("iso8859_11", Codec::Page(10021)),
    ("iso8859_13", Codec::Page(28603)),
    (
        "iso8859_14",
        Codec::Single(
            "\u{80}\u{81}\u{82}\u{83}\u{84}\u{85}\u{86}\u{87}\u{88}\u{89}\u{8a}\u{8b}\u{8c}\u{8d}\u{8e}\u{8f}\u{90}\u{91}\u{92}\u{93}\u{94}\u{95}\u{96}\u{97}\u{98}\u{99}\u{9a}\u{9b}\u{9c}\u{9d}\u{9e}\u{9f}\u{a0}\u{1e02}\u{1e03}\u{a3}\u{010a}\u{010b}\u{1e0a}\u{a7}\u{1e80}\u{a9}\u{1e82}\u{1e0b}\u{1ef2}\u{ad}\u{ae}\u{0178}\u{1e1e}\u{1e1f}\u{0120}\u{0121}\u{1e40}\u{1e41}\u{b6}\u{1e56}\u{1e81}\u{1e57}\u{1e83}\u{1e60}\u{1ef3}\u{1e84}\u{1e85}\u{1e61}\u{c0}\u{c1}\u{c2}\u{c3}\u{c4}\u{c5}\u{c6}\u{c7}\u{c8}\u{c9}\u{ca}\u{cb}\u{cc}\u{cd}\u{ce}\u{cf}\u{0174}\u{d1}\u{d2}\u{d3}\u{d4}\u{d5}\u{d6}\u{1e6a}\u{d8}\u{d9}\u{da}\u{db}\u{dc}\u{dd}\u{0176}\u{df}\u{e0}\u{e1}\u{e2}\u{e3}\u{e4}\u{e5}\u{e6}\u{e7}\u{e8}\u{e9}\u{ea}\u{eb}\u{ec}\u{ed}\u{ee}\u{ef}\u{0175}\u{f1}\u{f2}\u{f3}\u{f4}\u{f5}\u{f6}\u{1e6b}\u{f8}\u{f9}\u{fa}\u{fb}\u{fc}\u{fd}\u{0177}\u{ff}",
        ),
    ),
    ("iso8859_15", Codec::Page(28605)),
    (
        "iso8859_16",
        Codec::Single(
            "\u{80}\u{81}\u{82}\u{83}\u{84}\u{85}\u{86}\u{87}\u{88}\u{89}\u{8a}\u{8b}\u{8c}\u{8d}\u{8e}\u{8f}\u{90}\u{91}\u{92}\u{93}\u{94}\u{95}\u{96}\u{97}\u{98}\u{99}\u{9a}\u{9b}\u{9c}\u{9d}\u{9e}\u{9f}\u{a0}\u{0104}\u{0105}\u{0141}\u{20ac}\u{201e}\u{0160}\u{a7}\u{0161}\u{a9}\u{0218}\u{ab}\u{0179}\u{ad}\u{017a}\u{017b}\u{b0}\u{b1}\u{010c}\u{0142}\u{017d}\u{201d}\u{b6}\u{b7}\u{017e}\u{010d}\u{0219}\u{bb}\u{0152}\u{0153}\u{0178}\u{017c}\u{c0}\u{c1}\u{c2}\u{0102}\u{c4}\u{0106}\u{c6}\u{c7}\u{c8}\u{c9}\u{ca}\u{cb}\u{cc}\u{cd}\u{ce}\u{cf}\u{0110}\u{0143}\u{d2}\u{d3}\u{d4}\u{0150}\u{d6}\u{015a}\u{0170}\u{d9}\u{da}\u{db}\u{dc}\u{0118}\u{021a}\u{df}\u{e0}\u{e1}\u{e2}\u{0103}\u{e4}\u{0107}\u{e6}\u{e7}\u{e8}\u{e9}\u{ea}\u{eb}\u{ec}\u{ed}\u{ee}\u{ef}\u{0111}\u{0144}\u{f2}\u{f3}\u{f4}\u{0151}\u{f6}\u{015b}\u{0171}\u{f9}\u{fa}\u{fb}\u{fc}\u{0119}\u{021b}\u{ff}",
        ),
    ),
    ("iso8859_2", Codec::Page(870)),
    ("iso8859_3", Codec::Page(28593)),
    ("iso8859_4", Codec::Page(28594)),
    ("iso8859_5", Codec::Page(28595)),
    ("iso8859_6", Codec::Page(708)),
    ("iso8859_7", Codec::Page(28597)),
    ("iso8859_8", Codec::Page(10005)),
    ("iso8859_9", Codec::Page(28599)),
    ("johab", Codec::Page(1361)),
    (
        "koi8_r",
        Codec::Single(
            "\u{2500}\u{2502}\u{250c}\u{2510}\u{2514}\u{2518}\u{251c}\u{2524}\u{252c}\u{2534}\u{253c}\u{2580}\u{2584}\u{2588}\u{258c}\u{2590}\u{2591}\u{2592}\u{2593}\u{2320}\u{25a0}\u{2219}\u{221a}\u{2248}\u{2264}\u{2265}\u{a0}\u{2321}\u{b0}\u{b2}\u{b7}\u{f7}\u{2550}\u{2551}\u{2552}\u{0451}\u{2553}\u{2554}\u{2555}\u{2556}\u{2557}\u{2558}\u{2559}\u{255a}\u{255b}\u{255c}\u{255d}\u{255e}\u{255f}\u{2560}\u{2561}\u{0401}\u{2562}\u{2563}\u{2564}\u{2565}\u{2566}\u{2567}\u{2568}\u{2569}\u{256a}\u{256b}\u{256c}\u{a9}\u{044e}\u{0430}\u{0431}\u{0446}\u{0434}\u{0435}\u{0444}\u{0433}\u{0445}\u{0438}\u{0439}\u{043a}\u{043b}\u{043c}\u{043d}\u{043e}\u{043f}\u{044f}\u{0440}\u{0441}\u{0442}\u{0443}\u{0436}\u{0432}\u{044c}\u{044b}\u{0437}\u{0448}\u{044d}\u{0449}\u{0447}\u{044a}\u{042e}\u{0410}\u{0411}\u{0426}\u{0414}\u{0415}\u{0424}\u{0413}\u{0425}\u{0418}\u{0419}\u{041a}\u{041b}\u{041c}\u{041d}\u{041e}\u{041f}\u{042f}\u{0420}\u{0421}\u{0422}\u{0423}\u{0416}\u{0412}\u{042c}\u{042b}\u{0417}\u{0428}\u{042d}\u{0429}\u{0427}\u{042a}",
        ),
    ),
    (
        "koi8_t",
        Codec::Single(
            "\u{049b}\u{0493}\u{201a}\u{0492}\u{201e}\u{2026}\u{2020}\u{2021}\u{fffd}\u{2030}\u{04b3}\u{2039}\u{04b2}\u{04b7}\u{04b6}\u{fffd}\u{049a}\u{2018}\u{2019}\u{201c}\u{201d}\u{2022}\u{2013}\u{2014}\u{fffd}\u{2122}\u{fffd}\u{203a}\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{04ef}\u{04ee}\u{0451}\u{a4}\u{04e3}\u{a6}\u{a7}\u{fffd}\u{fffd}\u{fffd}\u{ab}\u{ac}\u{ad}\u{ae}\u{fffd}\u{b0}\u{b1}\u{b2}\u{0401}\u{fffd}\u{04e2}\u{b6}\u{b7}\u{fffd}\u{2116}\u{fffd}\u{bb}\u{fffd}\u{fffd}\u{fffd}\u{a9}\u{044e}\u{0430}\u{0431}\u{0446}\u{0434}\u{0435}\u{0444}\u{0433}\u{0445}\u{0438}\u{0439}\u{043a}\u{043b}\u{043c}\u{043d}\u{043e}\u{043f}\u{044f}\u{0440}\u{0441}\u{0442}\u{0443}\u{0436}\u{0432}\u{044c}\u{044b}\u{0437}\u{0448}\u{044d}\u{0449}\u{0447}\u{044a}\u{042e}\u{0410}\u{0411}\u{0426}\u{0414}\u{0415}\u{0424}\u{0413}\u{0425}\u{0418}\u{0419}\u{041a}\u{041b}\u{041c}\u{041d}\u{041e}\u{041f}\u{042f}\u{0420}\u{0421}\u{0422}\u{0423}\u{0416}\u{0412}\u{042c}\u{042b}\u{0417}\u{0428}\u{042d}\u{0429}\u{0427}\u{042a}",
        ),
    ),
    (
        "koi8_u",
        Codec::Single(
            "\u{2500}\u{2502}\u{250c}\u{2510}\u{2514}\u{2518}\u{251c}\u{2524}\u{252c}\u{2534}\u{253c}\u{2580}\u{2584}\u{2588}\u{258c}\u{2590}\u{2591}\u{2592}\u{2593}\u{2320}\u{25a0}\u{2219}\u{221a}\u{2248}\u{2264}\u{2265}\u{a0}\u{2321}\u{b0}\u{b2}\u{b7}\u{f7}\u{2550}\u{2551}\u{2552}\u{0451}\u{0454}\u{2554}\u{0456}\u{0457}\u{2557}\u{2558}\u{2559}\u{255a}\u{255b}\u{0491}\u{255d}\u{255e}\u{255f}\u{2560}\u{2561}\u{0401}\u{0404}\u{2563}\u{0406}\u{0407}\u{2566}\u{2567}\u{2568}\u{2569}\u{256a}\u{0490}\u{256c}\u{a9}\u{044e}\u{0430}\u{0431}\u{0446}\u{0434}\u{0435}\u{0444}\u{0433}\u{0445}\u{0438}\u{0439}\u{043a}\u{043b}\u{043c}\u{043d}\u{043e}\u{043f}\u{044f}\u{0440}\u{0441}\u{0442}\u{0443}\u{0436}\u{0432}\u{044c}\u{044b}\u{0437}\u{0448}\u{044d}\u{0449}\u{0447}\u{044a}\u{042e}\u{0410}\u{0411}\u{0426}\u{0414}\u{0415}\u{0424}\u{0413}\u{0425}\u{0418}\u{0419}\u{041a}\u{041b}\u{041c}\u{041d}\u{041e}\u{041f}\u{042f}\u{0420}\u{0421}\u{0422}\u{0423}\u{0416}\u{0412}\u{042c}\u{042b}\u{0417}\u{0428}\u{042d}\u{0429}\u{0427}\u{042a}",
        ),
    ),
    (
        "kz1048",
        Codec::Single(
            "\u{0402}\u{0403}\u{201a}\u{0453}\u{201e}\u{2026}\u{2020}\u{2021}\u{20ac}\u{2030}\u{0409}\u{2039}\u{040a}\u{049a}\u{04ba}\u{040f}\u{0452}\u{2018}\u{2019}\u{201c}\u{201d}\u{2022}\u{2013}\u{2014}\u{fffd}\u{2122}\u{0459}\u{203a}\u{045a}\u{049b}\u{04bb}\u{045f}\u{a0}\u{04b0}\u{04b1}\u{04d8}\u{a4}\u{04e8}\u{a6}\u{a7}\u{0401}\u{a9}\u{0492}\u{ab}\u{ac}\u{ad}\u{ae}\u{04ae}\u{b0}\u{b1}\u{0406}\u{0456}\u{04e9}\u{b5}\u{b6}\u{b7}\u{0451}\u{2116}\u{0493}\u{bb}\u{04d9}\u{04a2}\u{04a3}\u{04af}\u{0410}\u{0411}\u{0412}\u{0413}\u{0414}\u{0415}\u{0416}\u{0417}\u{0418}\u{0419}\u{041a}\u{041b}\u{041c}\u{041d}\u{041e}\u{041f}\u{0420}\u{0421}\u{0422}\u{0423}\u{0424}\u{0425}\u{0426}\u{0427}\u{0428}\u{0429}\u{042a}\u{042b}\u{042c}\u{042d}\u{042e}\u{042f}\u{0430}\u{0431}\u{0432}\u{0433}\u{0434}\u{0435}\u{0436}\u{0437}\u{0438}\u{0439}\u{043a}\u{043b}\u{043c}\u{043d}\u{043e}\u{043f}\u{0440}\u{0441}\u{0442}\u{0443}\u{0444}\u{0445}\u{0446}\u{0447}\u{0448}\u{0449}\u{044a}\u{044b}\u{044c}\u{044d}\u{044e}\u{044f}",
        ),
    ),
    ("latin_1", Codec::Latin1),
    ("mac_arabic", Codec::Page(10004)),
    (
        "mac_croatian",
        Codec::Single(
            "\u{c4}\u{c5}\u{c7}\u{c9}\u{d1}\u{d6}\u{dc}\u{e1}\u{e0}\u{e2}\u{e4}\u{e3}\u{e5}\u{e7}\u{e9}\u{e8}\u{ea}\u{eb}\u{ed}\u{ec}\u{ee}\u{ef}\u{f1}\u{f3}\u{f2}\u{f4}\u{f6}\u{f5}\u{fa}\u{f9}\u{fb}\u{fc}\u{2020}\u{b0}\u{a2}\u{a3}\u{a7}\u{2022}\u{b6}\u{df}\u{ae}\u{0160}\u{2122}\u{b4}\u{a8}\u{2260}\u{017d}\u{d8}\u{221e}\u{b1}\u{2264}\u{2265}\u{2206}\u{b5}\u{2202}\u{2211}\u{220f}\u{0161}\u{222b}\u{aa}\u{ba}\u{03a9}\u{017e}\u{f8}\u{bf}\u{a1}\u{ac}\u{221a}\u{0192}\u{2248}\u{0106}\u{ab}\u{010c}\u{2026}\u{a0}\u{c0}\u{c3}\u{d5}\u{0152}\u{0153}\u{0110}\u{2014}\u{201c}\u{201d}\u{2018}\u{2019}\u{f7}\u{25ca}\u{f8ff}\u{a9}\u{2044}\u{20ac}\u{2039}\u{203a}\u{c6}\u{bb}\u{2013}\u{b7}\u{201a}\u{201e}\u{2030}\u{c2}\u{0107}\u{c1}\u{010d}\u{c8}\u{cd}\u{ce}\u{cf}\u{cc}\u{d3}\u{d4}\u{0111}\u{d2}\u{da}\u{db}\u{d9}\u{0131}\u{02c6}\u{02dc}\u{af}\u{03c0}\u{cb}\u{02da}\u{b8}\u{ca}\u{e6}\u{02c7}",
        ),
    ),
    ("mac_cyrillic", Codec::Page(10007)),
    (
        "mac_farsi",
        Codec::Single(
            "\u{c4}\u{a0}\u{c7}\u{c9}\u{d1}\u{d6}\u{dc}\u{e1}\u{e0}\u{e2}\u{e4}\u{06ba}\u{ab}\u{e7}\u{e9}\u{e8}\u{ea}\u{eb}\u{ed}\u{2026}\u{ee}\u{ef}\u{f1}\u{f3}\u{bb}\u{f4}\u{f6}\u{f7}\u{fa}\u{f9}\u{fb}\u{fc} !\"#$\u{066a}&'()*+\u{060c}-./\u{06f0}\u{06f1}\u{06f2}\u{06f3}\u{06f4}\u{06f5}\u{06f6}\u{06f7}\u{06f8}\u{06f9}:\u{061b}<=>\u{061f}\u{274a}\u{0621}\u{0622}\u{0623}\u{0624}\u{0625}\u{0626}\u{0627}\u{0628}\u{0629}\u{062a}\u{062b}\u{062c}\u{062d}\u{062e}\u{062f}\u{0630}\u{0631}\u{0632}\u{0633}\u{0634}\u{0635}\u{0636}\u{0637}\u{0638}\u{0639}\u{063a}[\\]^_\u{0640}\u{0641}\u{0642}\u{0643}\u{0644}\u{0645}\u{0646}\u{0647}\u{0648}\u{0649}\u{064a}\u{064b}\u{064c}\u{064d}\u{064e}\u{064f}\u{0650}\u{0651}\u{0652}\u{067e}\u{0679}\u{0686}\u{06d5}\u{06a4}\u{06af}\u{0688}\u{0691}{|}\u{0698}\u{06d2}",
        ),
    ),
    ("mac_greek", Codec::Page(10006)),
    ("mac_iceland", Codec::Page(10079)),
    ("mac_latin2", Codec::Page(10029)),
    ("mac_roman", Codec::Page(10000)),
    (
        "mac_romanian",
        Codec::Single(
            "\u{c4}\u{c5}\u{c7}\u{c9}\u{d1}\u{d6}\u{dc}\u{e1}\u{e0}\u{e2}\u{e4}\u{e3}\u{e5}\u{e7}\u{e9}\u{e8}\u{ea}\u{eb}\u{ed}\u{ec}\u{ee}\u{ef}\u{f1}\u{f3}\u{f2}\u{f4}\u{f6}\u{f5}\u{fa}\u{f9}\u{fb}\u{fc}\u{2020}\u{b0}\u{a2}\u{a3}\u{a7}\u{2022}\u{b6}\u{df}\u{ae}\u{a9}\u{2122}\u{b4}\u{a8}\u{2260}\u{0102}\u{0218}\u{221e}\u{b1}\u{2264}\u{2265}\u{a5}\u{b5}\u{2202}\u{2211}\u{220f}\u{03c0}\u{222b}\u{aa}\u{ba}\u{03a9}\u{0103}\u{0219}\u{bf}\u{a1}\u{ac}\u{221a}\u{0192}\u{2248}\u{2206}\u{ab}\u{bb}\u{2026}\u{a0}\u{c0}\u{c3}\u{d5}\u{0152}\u{0153}\u{2013}\u{2014}\u{201c}\u{201d}\u{2018}\u{2019}\u{f7}\u{25ca}\u{ff}\u{0178}\u{2044}\u{20ac}\u{2039}\u{203a}\u{021a}\u{021b}\u{2021}\u{b7}\u{201a}\u{201e}\u{2030}\u{c2}\u{ca}\u{c1}\u{cb}\u{c8}\u{cd}\u{ce}\u{cf}\u{cc}\u{d3}\u{d4}\u{f8ff}\u{d2}\u{da}\u{db}\u{d9}\u{0131}\u{02c6}\u{02dc}\u{af}\u{02d8}\u{02d9}\u{02da}\u{b8}\u{02dd}\u{02db}\u{02c7}",
        ),
    ),
    ("mac_turkish", Codec::Page(10081)),
    (
        "palmos",
        Codec::Single(
            "\u{20ac}\u{81}\u{201a}\u{0192}\u{201e}\u{2026}\u{2020}\u{2021}\u{02c6}\u{2030}\u{0160}\u{2039}\u{0152}\u{2666}\u{2663}\u{2665}\u{2660}\u{2018}\u{2019}\u{201c}\u{201d}\u{2022}\u{2013}\u{2014}\u{02dc}\u{2122}\u{0161}\u{203a}\u{0153}\u{9d}\u{9e}\u{0178}\u{a0}\u{a1}\u{a2}\u{a3}\u{a4}\u{a5}\u{a6}\u{a7}\u{a8}\u{a9}\u{aa}\u{ab}\u{ac}\u{ad}\u{ae}\u{af}\u{b0}\u{b1}\u{b2}\u{b3}\u{b4}\u{b5}\u{b6}\u{b7}\u{b8}\u{b9}\u{ba}\u{bb}\u{bc}\u{bd}\u{be}\u{bf}\u{c0}\u{c1}\u{c2}\u{c3}\u{c4}\u{c5}\u{c6}\u{c7}\u{c8}\u{c9}\u{ca}\u{cb}\u{cc}\u{cd}\u{ce}\u{cf}\u{d0}\u{d1}\u{d2}\u{d3}\u{d4}\u{d5}\u{d6}\u{d7}\u{d8}\u{d9}\u{da}\u{db}\u{dc}\u{dd}\u{de}\u{df}\u{e0}\u{e1}\u{e2}\u{e3}\u{e4}\u{e5}\u{e6}\u{e7}\u{e8}\u{e9}\u{ea}\u{eb}\u{ec}\u{ed}\u{ee}\u{ef}\u{f0}\u{f1}\u{f2}\u{f3}\u{f4}\u{f5}\u{f6}\u{f7}\u{f8}\u{f9}\u{fa}\u{fb}\u{fc}\u{fd}\u{fe}\u{ff}",
        ),
    ),
    ("ptcp154", Codec::Page(154)),
    ("punycode", Codec::Punycode),
    ("raw_unicode_escape", Codec::RawUnicodeEscape),
    ("shift_jis", Codec::Page(10001)),
    (
        "shift_jis_2004",
        Codec::Approx(&encoding_rs::SHIFT_JIS_INIT),
    ),
    (
        "shift_jisx0213",
        Codec::Approx(&encoding_rs::SHIFT_JIS_INIT),
    ),
    (
        "tis_620",
        Codec::Single(
            "\u{80}\u{81}\u{82}\u{83}\u{84}\u{85}\u{86}\u{87}\u{88}\u{89}\u{8a}\u{8b}\u{8c}\u{8d}\u{8e}\u{8f}\u{90}\u{91}\u{92}\u{93}\u{94}\u{95}\u{96}\u{97}\u{98}\u{99}\u{9a}\u{9b}\u{9c}\u{9d}\u{9e}\u{9f}\u{fffd}\u{0e01}\u{0e02}\u{0e03}\u{0e04}\u{0e05}\u{0e06}\u{0e07}\u{0e08}\u{0e09}\u{0e0a}\u{0e0b}\u{0e0c}\u{0e0d}\u{0e0e}\u{0e0f}\u{0e10}\u{0e11}\u{0e12}\u{0e13}\u{0e14}\u{0e15}\u{0e16}\u{0e17}\u{0e18}\u{0e19}\u{0e1a}\u{0e1b}\u{0e1c}\u{0e1d}\u{0e1e}\u{0e1f}\u{0e20}\u{0e21}\u{0e22}\u{0e23}\u{0e24}\u{0e25}\u{0e26}\u{0e27}\u{0e28}\u{0e29}\u{0e2a}\u{0e2b}\u{0e2c}\u{0e2d}\u{0e2e}\u{0e2f}\u{0e30}\u{0e31}\u{0e32}\u{0e33}\u{0e34}\u{0e35}\u{0e36}\u{0e37}\u{0e38}\u{0e39}\u{0e3a}\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{0e3f}\u{0e40}\u{0e41}\u{0e42}\u{0e43}\u{0e44}\u{0e45}\u{0e46}\u{0e47}\u{0e48}\u{0e49}\u{0e4a}\u{0e4b}\u{0e4c}\u{0e4d}\u{0e4e}\u{0e4f}\u{0e50}\u{0e51}\u{0e52}\u{0e53}\u{0e54}\u{0e55}\u{0e56}\u{0e57}\u{0e58}\u{0e59}\u{0e5a}\u{0e5b}\u{fffd}\u{fffd}\u{fffd}\u{fffd}",
        ),
    ),
    ("undefined", Codec::Undefined),
    ("unicode_escape", Codec::UnicodeEscape),
    ("utf_16", Codec::Utf16(0)),
    ("utf_16_be", Codec::Utf16(1)),
    ("utf_16_le", Codec::Utf16(-1)),
    ("utf_32", Codec::Utf32(0)),
    ("utf_32_be", Codec::Utf32(1)),
    ("utf_32_le", Codec::Utf32(-1)),
    ("utf_7", Codec::Utf7),
    ("utf_8", Codec::Utf8),
    ("utf_8_sig", Codec::Utf8Sig),
];

/// `encodings.aliases`, only those of text codecs.
const ALIASES: &[(&str, &str)] = &[
    ("037", "cp037"),
    ("1026", "cp1026"),
    ("1125", "cp1125"),
    ("1140", "cp1140"),
    ("1250", "cp1250"),
    ("1251", "cp1251"),
    ("1252", "cp1252"),
    ("1253", "cp1253"),
    ("1254", "cp1254"),
    ("1255", "cp1255"),
    ("1256", "cp1256"),
    ("1257", "cp1257"),
    ("1258", "cp1258"),
    ("273", "cp273"),
    ("424", "cp424"),
    ("437", "cp437"),
    ("500", "cp500"),
    ("646", "ascii"),
    ("775", "cp775"),
    ("850", "cp850"),
    ("852", "cp852"),
    ("855", "cp855"),
    ("857", "cp857"),
    ("858", "cp858"),
    ("860", "cp860"),
    ("861", "cp861"),
    ("862", "cp862"),
    ("863", "cp863"),
    ("864", "cp864"),
    ("865", "cp865"),
    ("866", "cp866"),
    ("869", "cp869"),
    ("874", "cp874"),
    ("8859", "latin_1"),
    ("932", "cp932"),
    ("936", "gbk"),
    ("949", "cp949"),
    ("950", "cp950"),
    ("ansi_x3.4_1968", "ascii"),
    ("ansi_x3.4_1986", "ascii"),
    ("ansi_x3_4_1968", "ascii"),
    ("arabic", "iso8859_6"),
    ("asmo_708", "iso8859_6"),
    ("big5_hkscs", "big5hkscs"),
    ("big5_tw", "big5"),
    ("chinese", "gb2312"),
    ("cp00858", "cp858"),
    ("cp01140", "cp1140"),
    ("cp1051", "hp_roman8"),
    ("cp1361", "johab"),
    ("cp154", "ptcp154"),
    ("cp367", "ascii"),
    ("cp65001", "utf_8"),
    ("cp819", "latin_1"),
    ("cp866u", "cp1125"),
    ("cp936", "gbk"),
    ("cp_gr", "cp869"),
    ("cp_is", "cp861"),
    ("csHPRoman8", "hp_roman8"),
    ("csascii", "ascii"),
    ("csbig5", "big5"),
    ("cseuckr", "euc_kr"),
    ("csibm00858", "cp858"),
    ("csibm01140", "cp1140"),
    ("csibm037", "cp037"),
    ("csibm1026", "cp1026"),
    ("csibm273", "cp273"),
    ("csibm424", "cp424"),
    ("csibm500", "cp500"),
    ("csibm855", "cp855"),
    ("csibm857", "cp857"),
    ("csibm858", "cp858"),
    ("csibm860", "cp860"),
    ("csibm861", "cp861"),
    ("csibm863", "cp863"),
    ("csibm864", "cp864"),
    ("csibm865", "cp865"),
    ("csibm866", "cp866"),
    ("csibm869", "cp869"),
    ("csiso2022jp", "iso2022_jp"),
    ("csiso2022kr", "iso2022_kr"),
    ("csiso58gb231280", "gb2312"),
    ("csisolatin1", "latin_1"),
    ("csisolatin2", "iso8859_2"),
    ("csisolatin3", "iso8859_3"),
    ("csisolatin4", "iso8859_4"),
    ("csisolatin5", "iso8859_9"),
    ("csisolatin6", "iso8859_10"),
    ("csisolatinarabic", "iso8859_6"),
    ("csisolatincyrillic", "iso8859_5"),
    ("csisolatingreek", "iso8859_7"),
    ("csisolatinhebrew", "iso8859_8"),
    ("cskoi8r", "koi8_r"),
    ("cspc775baltic", "cp775"),
    ("cspc850multilingual", "cp850"),
    ("cspc862latinhebrew", "cp862"),
    ("cspc8codepage437", "cp437"),
    ("cspcp852", "cp852"),
    ("csptcp154", "ptcp154"),
    ("csshiftjis", "shift_jis"),
    ("cyrillic", "iso8859_5"),
    ("cyrillic_asian", "ptcp154"),
    ("ebcdic_cp_be", "cp500"),
    ("ebcdic_cp_ca", "cp037"),
    ("ebcdic_cp_ch", "cp500"),
    ("ebcdic_cp_he", "cp424"),
    ("ebcdic_cp_nl", "cp037"),
    ("ebcdic_cp_us", "cp037"),
    ("ebcdic_cp_wt", "cp037"),
    ("ebcdic_us_37_euro", "cp1140"),
    ("ecma_114", "iso8859_6"),
    ("ecma_118", "iso8859_7"),
    ("elot_928", "iso8859_7"),
    ("euc_cn", "gb2312"),
    ("euc_jis2004", "euc_jis_2004"),
    ("euccn", "gb2312"),
    ("eucgb2312_cn", "gb2312"),
    ("eucjis2004", "euc_jis_2004"),
    ("eucjisx0213", "euc_jisx0213"),
    ("eucjp", "euc_jp"),
    ("euckr", "euc_kr"),
    ("gb18030_2000", "gb18030"),
    ("gb2312_1980", "gb2312"),
    ("gb2312_80", "gb2312"),
    ("greek", "iso8859_7"),
    ("greek8", "iso8859_7"),
    ("hebrew", "iso8859_8"),
    ("hkscs", "big5hkscs"),
    ("hz_gb", "hz"),
    ("hz_gb_2312", "hz"),
    ("hzgb", "hz"),
    ("ibm00858", "cp858"),
    ("ibm01140", "cp1140"),
    ("ibm037", "cp037"),
    ("ibm039", "cp037"),
    ("ibm1026", "cp1026"),
    ("ibm1051", "hp_roman8"),
    ("ibm1125", "cp1125"),
    ("ibm1140", "cp1140"),
    ("ibm273", "cp273"),
    ("ibm367", "ascii"),
    ("ibm424", "cp424"),
    ("ibm437", "cp437"),
    ("ibm500", "cp500"),
    ("ibm775", "cp775"),
    ("ibm819", "latin_1"),
    ("ibm850", "cp850"),
    ("ibm852", "cp852"),
    ("ibm855", "cp855"),
    ("ibm857", "cp857"),
    ("ibm858", "cp858"),
    ("ibm860", "cp860"),
    ("ibm861", "cp861"),
    ("ibm862", "cp862"),
    ("ibm863", "cp863"),
    ("ibm864", "cp864"),
    ("ibm865", "cp865"),
    ("ibm866", "cp866"),
    ("ibm869", "cp869"),
    ("iso2022jp", "iso2022_jp"),
    ("iso2022jp_1", "iso2022_jp_1"),
    ("iso2022jp_2", "iso2022_jp_2"),
    ("iso2022jp_2004", "iso2022_jp_2004"),
    ("iso2022jp_3", "iso2022_jp_3"),
    ("iso2022jp_ext", "iso2022_jp_ext"),
    ("iso2022kr", "iso2022_kr"),
    ("iso646_us", "ascii"),
    ("iso8859", "latin_1"),
    ("iso8859_1", "latin_1"),
    ("iso_2022_jp", "iso2022_jp"),
    ("iso_2022_jp_1", "iso2022_jp_1"),
    ("iso_2022_jp_2", "iso2022_jp_2"),
    ("iso_2022_jp_2004", "iso2022_jp_2004"),
    ("iso_2022_jp_3", "iso2022_jp_3"),
    ("iso_2022_jp_ext", "iso2022_jp_ext"),
    ("iso_2022_kr", "iso2022_kr"),
    ("iso_646.irv_1991", "ascii"),
    ("iso_8859_1", "latin_1"),
    ("iso_8859_10", "iso8859_10"),
    ("iso_8859_10_1992", "iso8859_10"),
    ("iso_8859_11", "iso8859_11"),
    ("iso_8859_11_2001", "iso8859_11"),
    ("iso_8859_13", "iso8859_13"),
    ("iso_8859_14", "iso8859_14"),
    ("iso_8859_14_1998", "iso8859_14"),
    ("iso_8859_15", "iso8859_15"),
    ("iso_8859_16", "iso8859_16"),
    ("iso_8859_16_2001", "iso8859_16"),
    ("iso_8859_1_1987", "latin_1"),
    ("iso_8859_2", "iso8859_2"),
    ("iso_8859_2_1987", "iso8859_2"),
    ("iso_8859_3", "iso8859_3"),
    ("iso_8859_3_1988", "iso8859_3"),
    ("iso_8859_4", "iso8859_4"),
    ("iso_8859_4_1988", "iso8859_4"),
    ("iso_8859_5", "iso8859_5"),
    ("iso_8859_5_1988", "iso8859_5"),
    ("iso_8859_6", "iso8859_6"),
    ("iso_8859_6_1987", "iso8859_6"),
    ("iso_8859_7", "iso8859_7"),
    ("iso_8859_7_1987", "iso8859_7"),
    ("iso_8859_8", "iso8859_8"),
    ("iso_8859_8_1988", "iso8859_8"),
    ("iso_8859_8_e", "iso8859_8"),
    ("iso_8859_8_i", "iso8859_8"),
    ("iso_8859_9", "iso8859_9"),
    ("iso_8859_9_1989", "iso8859_9"),
    ("iso_celtic", "iso8859_14"),
    ("iso_ir_100", "latin_1"),
    ("iso_ir_101", "iso8859_2"),
    ("iso_ir_109", "iso8859_3"),
    ("iso_ir_110", "iso8859_4"),
    ("iso_ir_126", "iso8859_7"),
    ("iso_ir_127", "iso8859_6"),
    ("iso_ir_138", "iso8859_8"),
    ("iso_ir_144", "iso8859_5"),
    ("iso_ir_148", "iso8859_9"),
    ("iso_ir_157", "iso8859_10"),
    ("iso_ir_166", "tis_620"),
    ("iso_ir_199", "iso8859_14"),
    ("iso_ir_226", "iso8859_16"),
    ("iso_ir_58", "gb2312"),
    ("iso_ir_6", "ascii"),
    ("jisx0213", "euc_jis_2004"),
    ("korean", "euc_kr"),
    ("ks_c_5601", "euc_kr"),
    ("ks_c_5601_1987", "euc_kr"),
    ("ks_x_1001", "euc_kr"),
    ("ksc5601", "euc_kr"),
    ("ksx1001", "euc_kr"),
    ("kz_1048", "kz1048"),
    ("l1", "latin_1"),
    ("l10", "iso8859_16"),
    ("l2", "iso8859_2"),
    ("l3", "iso8859_3"),
    ("l4", "iso8859_4"),
    ("l5", "iso8859_9"),
    ("l6", "iso8859_10"),
    ("l7", "iso8859_13"),
    ("l8", "iso8859_14"),
    ("l9", "iso8859_15"),
    ("latin", "latin_1"),
    ("latin1", "latin_1"),
    ("latin10", "iso8859_16"),
    ("latin2", "iso8859_2"),
    ("latin3", "iso8859_3"),
    ("latin4", "iso8859_4"),
    ("latin5", "iso8859_9"),
    ("latin6", "iso8859_10"),
    ("latin7", "iso8859_13"),
    ("latin8", "iso8859_14"),
    ("latin9", "iso8859_15"),
    ("mac_centeuro", "mac_latin2"),
    ("maccentraleurope", "mac_latin2"),
    ("maccyrillic", "mac_cyrillic"),
    ("macgreek", "mac_greek"),
    ("maciceland", "mac_iceland"),
    ("macintosh", "mac_roman"),
    ("maclatin2", "mac_latin2"),
    ("macroman", "mac_roman"),
    ("macturkish", "mac_turkish"),
    ("ms1361", "johab"),
    ("ms874", "cp874"),
    ("ms932", "cp932"),
    ("ms936", "gbk"),
    ("ms949", "cp949"),
    ("ms950", "cp950"),
    ("ms_kanji", "cp932"),
    ("mskanji", "cp932"),
    ("pc_multilingual_850_euro", "cp858"),
    ("pt154", "ptcp154"),
    ("r8", "hp_roman8"),
    ("rk1048", "kz1048"),
    ("roman8", "hp_roman8"),
    ("ruscii", "cp1125"),
    ("s_jis", "shift_jis"),
    ("s_jis_2004", "shift_jis_2004"),
    ("s_jisx0213", "shift_jisx0213"),
    ("shiftjis", "shift_jis"),
    ("shiftjis2004", "shift_jis_2004"),
    ("shiftjisx0213", "shift_jisx0213"),
    ("sjis", "shift_jis"),
    ("sjis_2004", "shift_jis_2004"),
    ("sjisx0213", "shift_jisx0213"),
    ("strk1048_2002", "kz1048"),
    ("thai", "iso8859_11"),
    ("tis620", "tis_620"),
    ("tis_620_0", "tis_620"),
    ("tis_620_2529_0", "tis_620"),
    ("tis_620_2529_1", "tis_620"),
    ("u16", "utf_16"),
    ("u32", "utf_32"),
    ("u7", "utf_7"),
    ("u8", "utf_8"),
    ("u_jis", "euc_jp"),
    ("uhc", "cp949"),
    ("ujis", "euc_jp"),
    ("unicode_1_1_utf_7", "utf_7"),
    ("unicodebigunmarked", "utf_16_be"),
    ("unicodelittleunmarked", "utf_16_le"),
    ("us", "ascii"),
    ("us_ascii", "ascii"),
    ("utf", "utf_8"),
    ("utf16", "utf_16"),
    ("utf32", "utf_32"),
    ("utf7", "utf_7"),
    ("utf8", "utf_8"),
    ("utf8_ucs2", "utf_8"),
    ("utf8_ucs4", "utf_8"),
    ("utf_16be", "utf_16_be"),
    ("utf_16le", "utf_16_le"),
    ("utf_32be", "utf_32_be"),
    ("utf_32le", "utf_32_le"),
    ("windows_1250", "cp1250"),
    ("windows_1251", "cp1251"),
    ("windows_1252", "cp1252"),
    ("windows_1253", "cp1253"),
    ("windows_1254", "cp1254"),
    ("windows_1255", "cp1255"),
    ("windows_1256", "cp1256"),
    ("windows_1257", "cp1257"),
    ("windows_1258", "cp1258"),
    ("windows_31j", "cp932"),
    ("windows_874", "cp874"),
    ("x_mac_japanese", "shift_jis"),
    ("x_mac_korean", "euc_kr"),
    ("x_mac_simp_chinese", "gb2312"),
    ("x_mac_trad_chinese", "big5"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Option<TextOrBytes> {
        Some(TextOrBytes::Text(value.to_owned()))
    }

    #[test]
    fn an_mht_walks_as_in_python() {
        let data = b"MIME-Version: 1.0\nContent-Type: multipart/related; boundary=\"b\"\n\npre\n--b\n\
            Content-Type: text/html\nContent-Transfer-Encoding: quoted-printable\n\ncaf=E9=\n!\n--b\n\
            Content-Type: application/x-mso; name=\"editdata.mso\"\n\
            Content-Transfer-Encoding: base64\n\nQWN0aXZl\nTWltZQ==\n--b\n\
            Content-Type: message/rfc822\n\nA: b\n\ninner\n--b--\nepilogue\n";
        let parts = parts(data).unwrap();
        let summary: Vec<_> = parts
            .iter()
            .map(|p| {
                (
                    p.content_type.as_str(),
                    p.filename.clone(),
                    p.payload.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("multipart/related", None, None),
                ("text/html", None, Some(&b"caf\xe9!"[..])),
                (
                    "application/x-mso",
                    text("editdata.mso"),
                    Some(&b"ActiveMime"[..])
                ),
                ("message/rfc822", None, None),
                ("text/plain", None, Some(&b"inner"[..])),
            ]
        );
    }

    #[test]
    fn a_filename_that_isnt_unicode_is_bytes_as_canon_gives() {
        let name = |value: &[u8]| {
            let data = [
                b"Content-Disposition: attachment; filename".as_slice(),
                value,
            ]
            .concat();
            parts(&data).unwrap().remove(0).filename
        };
        assert_eq!(
            name(b"*=raw-unicode-escape''%5Cud800.mso\n\nx"),
            Some(TextOrBytes::Bytes(Bytes(b"\xed\xa0\x80.mso".to_vec())))
        );
        assert_eq!(
            name(b"*=raw-unicode-escape''%5Cudc80a\n\nx"),
            Some(TextOrBytes::Bytes(Bytes(b"\x80a".to_vec())))
        );
        assert_eq!(name(b"=\"\xe9.txt\"\n\nx"), text("\u{fffd}.txt"));
    }

    #[test]
    fn payloads_decode_as_in_python() {
        let payload = |data: &[u8]| parts(data).unwrap().remove(0).payload.unwrap();
        assert_eq!(payload(b"A: b\nFrom x\n\nbody"), b"From x\nbody");
        assert_eq!(
            payload(b"Content-Transfer-Encoding: x-uuencode\n\nbegin 644 x\n#86)C\n \nend\n"),
            b"abc"
        );
        assert_eq!(
            payload(b"Content-Transfer-Encoding: base64\n\nQUJD!"),
            b"ABC"
        );
        assert_eq!(payload(b"Content-Transfer-Encoding: base64\n\nQ"), b"Q");
    }

    #[test]
    fn errors_are_pythons() {
        let nested = |depth: usize| {
            let mut data = Vec::new();
            for i in 0..depth {
                data.extend_from_slice(
                    format!("Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n").as_bytes(),
                );
            }
            data.push(b'x');
            data
        };
        let assertion = PyErr::new(
            "AssertionError",
            "_parse_headers fed line with no : and no leading WS",
        );
        assert_eq!(parts(b"no colon here\n\nbody").unwrap_err(), assertion);
        assert_eq!(parts(&nested(981)).unwrap_err(), assertion);
        assert_eq!(parts(&nested(982)).unwrap_err().kind, "RecursionError");
    }
}
