//! html2text 2025.4.15's `html2text(html)`, with its defaults, which ace3's `wordlist_from_email` reads an
//! email's body through. The text goes in the result as `email_body`, and the passwords to try are cut
//! from it, so a link's markup, a wrapped line or an escaped dot changes what's tried. No crate gives this
//! text: Rust's html2text and html2md wrap and mark up in their own ways. What its defaults turn off isn't
//! here: Google Docs mode, reference-style links, table padding, code marks, snob modes.

use std::sync::OnceLock;

use ace_mod_oletools::py::{PyErr, is_space, strip};
use ace_mod_oletools::textwrap::wrap_with;

use crate::htmlparser::{self, Handler};
use ace_pycompat::html::entities;

const BODY_WIDTH: usize = 78;
const PUNCTUATION: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const SLASH_CHARS: &str = "\\`*_{}[]()#+-.!";
const NBSP_HOLDER: &str = "&nbsp_place_holder;";

/// `config.UNIFIABLE`, with `nbsp` as `HTML2Text.__init__` leaves it.
const UNIFIABLE: &[(&str, u32, &str)] = &[
    ("rsquo", 0x2019, "'"),
    ("lsquo", 0x2018, "'"),
    ("rdquo", 0x201D, "\""),
    ("ldquo", 0x201C, "\""),
    ("copy", 0xA9, "(C)"),
    ("mdash", 0x2014, "--"),
    ("nbsp", 0xA0, NBSP_HOLDER),
    ("rarr", 0x2192, "->"),
    ("larr", 0x2190, "<-"),
    ("middot", 0xB7, "*"),
    ("ndash", 0x2013, "-"),
    ("oelig", 0x153, "oe"),
    ("aelig", 0xE6, "ae"),
    ("agrave", 0xE0, "a"),
    ("aacute", 0xE1, "a"),
    ("acirc", 0xE2, "a"),
    ("atilde", 0xE3, "a"),
    ("auml", 0xE4, "a"),
    ("aring", 0xE5, "a"),
    ("egrave", 0xE8, "e"),
    ("eacute", 0xE9, "e"),
    ("ecirc", 0xEA, "e"),
    ("euml", 0xEB, "e"),
    ("igrave", 0xEC, "i"),
    ("iacute", 0xED, "i"),
    ("icirc", 0xEE, "i"),
    ("iuml", 0xEF, "i"),
    ("ograve", 0xF2, "o"),
    ("oacute", 0xF3, "o"),
    ("ocirc", 0xF4, "o"),
    ("otilde", 0xF5, "o"),
    ("ouml", 0xF6, "o"),
    ("ugrave", 0xF9, "u"),
    ("uacute", 0xFA, "u"),
    ("ucirc", 0xFB, "u"),
    ("uuml", 0xFC, "u"),
    ("lrm", 0x200E, ""),
    ("rlm", 0x200F, ""),
];

const CONTROL_REPLACEMENTS: &[(u32, u32)] = &[
    (0x80, 0x20AC),
    (0x82, 0x201A),
    (0x83, 0x192),
    (0x84, 0x201E),
    (0x85, 0x2026),
    (0x86, 0x2020),
    (0x87, 0x2021),
    (0x88, 0x2C6),
    (0x89, 0x2030),
    (0x8A, 0x160),
    (0x8B, 0x2039),
    (0x8C, 0x152),
    (0x8E, 0x17D),
    (0x91, 0x2018),
    (0x92, 0x2019),
    (0x93, 0x201C),
    (0x94, 0x201D),
    (0x95, 0x2022),
    (0x96, 0x2013),
    (0x97, 0x2014),
    (0x98, 0x2DC),
    (0x99, 0x2122),
    (0x9A, 0x161),
    (0x9B, 0x203A),
    (0x9C, 0x153),
    (0x9E, 0x17E),
    (0x9F, 0x178),
];

fn is_decimal(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_digit();
    }
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"^\p{Nd}$").expect("a valid class"));
    let mut buffer = [0; 4];
    re.is_match(c.encode_utf8(&mut buffer))
}

/// `hn(tag)`.
fn hn(tag: &str) -> usize {
    let mut chars = tag.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some('h'), Some(n), None) if ('1'..='9').contains(&n) => n as usize - '0' as usize,
        _ => 0,
    }
}

/// `escape_md`.
fn escape_md(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '[' | ']' | '(' | ')') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `^(\s*)` then something, at every line start: the prefix's whitespace run is skipped as a whole
/// when it fails, since no later line start inside it can do better.
fn sub_at_line_starts(text: &str, rule: impl Fn(&[char], usize) -> Option<usize>) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut line_start = true;
    while at < chars.len() {
        if line_start {
            let mut after_space = at;
            while chars.get(after_space).copied().is_some_and(is_space) {
                after_space += 1;
            }
            if let Some(mark) = rule(&chars, after_space) {
                out.extend(&chars[at..mark]);
                out.push('\\');
                out.push(chars[mark]);
                at = mark + 1;
                line_start = false;
                continue;
            }
            if after_space > at {
                out.extend(&chars[at..after_space]);
                line_start = chars[after_space - 1] == '\n';
                at = after_space;
                continue;
            }
        }
        out.push(chars[at]);
        line_start = chars[at] == '\n';
        at += 1;
    }
    out
}

/// `escape_md_section(text)`.
fn escape_md_section(text: &str) -> String {
    let mut slashed = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().is_some_and(|next| SLASH_CHARS.contains(*next)) {
            slashed.push('\\');
        }
        slashed.push(c);
    }
    let dots = sub_at_line_starts(&slashed, |chars, at| {
        let mut end = at;
        while chars.get(end).copied().is_some_and(is_decimal) {
            end += 1;
        }
        (end > at
            && chars.get(end) == Some(&'.')
            && chars.get(end + 1).copied().is_some_and(is_space))
        .then_some(end)
    });
    let pluses = sub_at_line_starts(&dots, |chars, at| {
        (chars.get(at) == Some(&'+') && chars.get(at + 1).copied().is_some_and(is_space))
            .then_some(at)
    });
    sub_at_line_starts(&pluses, |chars, at| {
        (chars.get(at) == Some(&'-')
            && chars
                .get(at + 1)
                .copied()
                .is_some_and(|c| is_space(c) || c == '-'))
        .then_some(at)
    })
}

/// `re.sub(r"\s+", " ", data)`.
fn collapse_space(data: &str) -> String {
    let mut out = String::with_capacity(data.len());
    let mut in_space = false;
    for c in data.chars() {
        if is_space(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    out
}

/// `int(text) - 1 + 1` as a list's numbering goes: None when it isn't a number. A number past `i128`
/// saturates, where Python would count on: it only numbers list items.
fn parse_start(text: &str) -> Option<i128> {
    let trimmed = strip(text);
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let mut value: i128 = 0;
    let mut last_underscore = true;
    let mut count = 0;
    for c in digits.chars() {
        if c == '_' {
            if last_underscore {
                return None;
            }
            last_underscore = true;
            continue;
        }
        let digit = if c.is_ascii() {
            c.to_digit(10)?
        } else if is_decimal(c) {
            // a decimal digit's block runs up from its zero in tens
            let mut zero = u32::from(c);
            while char::from_u32(zero - 1).is_some_and(is_decimal) && u32::from(c) - zero < 9 {
                zero -= 1;
            }
            u32::from(c) - zero
        } else {
            return None;
        };
        last_underscore = false;
        count += 1;
        value = value.saturating_mul(10).saturating_add(i128::from(digit));
    }
    if last_underscore || count > 4300 {
        return None;
    }
    Some(if negative { -value } else { value })
}

fn get_attr<'a>(attrs: &'a [(String, Option<String>)], name: &str) -> Option<Option<&'a str>> {
    attrs
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_deref())
}

/// `<a>`'s entry on `astack`.
#[derive(Debug, Clone)]
struct Anchor {
    href: String,
    title: Option<String>,
}

#[derive(Debug, Clone)]
struct List {
    ordered: bool,
    num: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Force {
    No,
    Yes,
    End,
}

#[derive(Debug, Default)]
struct Html2Text {
    split_next_td: bool,
    td_count: usize,
    table_start: bool,
    out: Vec<String>,
    quiet: i64,
    p_p: usize,
    start: bool,
    space: bool,
    astack: Vec<Option<Anchor>>,
    maybe_automatic_link: Option<String>,
    empty_link: bool,
    list: Vec<List>,
    blockquote: i64,
    pre: bool,
    startpre: bool,
    list_code_indent: String,
    code: bool,
    quote: bool,
    br_toggle: String,
    last_was_nl: bool,
    last_was_list: bool,
    abbr_title: Option<String>,
    abbr_data: Option<String>,
    abbr_list: Vec<(String, String)>,
    stressed: bool,
    preceding_stressed: bool,
    preceding_data: String,
    current_tag: String,
}

impl Html2Text {
    fn emit(&mut self, text: &str) {
        self.out.push(text.to_owned());
        if let Some(last) = text.chars().last() {
            self.last_was_nl = last == '\n';
        }
    }

    fn pbr(&mut self) {
        if self.p_p == 0 {
            self.p_p = 1;
        }
    }

    fn p(&mut self) {
        self.p_p = 2;
    }

    fn soft_br(&mut self) {
        self.pbr();
        "  ".clone_into(&mut self.br_toggle);
    }

    /// `o(data)`.
    fn o(&mut self, data: &str) {
        self.output(data, false, Force::No);
    }

    fn output(&mut self, data: &str, puredata: bool, force: Force) {
        if let Some(abbr) = &mut self.abbr_data {
            abbr.push_str(data);
        }
        if self.quiet != 0 {
            return;
        }
        let mut data = data.to_owned();
        if puredata && !self.pre {
            data = collapse_space(&data);
            if data.starts_with(' ') {
                self.space = true;
                data.remove(0);
            }
        }
        if data.is_empty() && force == Force::No {
            return;
        }
        if self.startpre && !data.starts_with('\n') && !data.starts_with("\r\n") {
            data.insert(0, '\n');
        }
        let blockquote = usize::try_from(self.blockquote).unwrap_or(0);
        let mut bq = ">".repeat(blockquote);
        if !(force != Force::No && data.starts_with('>')) && self.blockquote != 0 {
            bq.push(' ');
        }
        // ">" * a negative count is empty, and a negative blockquote is still true above
        let mut pre_indent = String::new();
        if self.pre {
            if !self.list.is_empty() {
                bq.push_str(&self.list_code_indent);
            }
            bq.push_str("    ");
            data = data.replace('\n', &format!("\n{bq}"));
            pre_indent.clone_from(&bq);
        }
        if self.startpre {
            self.startpre = false;
            if !self.list.is_empty() {
                // `data.lstrip("\n" + pre_indent)`
                let strip_set: Vec<char> = format!("\n{pre_indent}").chars().collect();
                data = data
                    .trim_start_matches(|c| strip_set.contains(&c))
                    .to_owned();
            }
        }
        if self.start {
            self.space = false;
            self.p_p = 0;
            self.start = false;
        }
        if force == Force::End {
            self.p_p = 0;
            self.emit("\n");
            self.space = false;
        }
        if self.p_p != 0 {
            let piece = format!("{}\n{bq}", self.br_toggle).repeat(self.p_p);
            self.emit(&piece);
            self.space = false;
            self.br_toggle.clear();
        }
        if self.space {
            if !self.last_was_nl {
                self.emit(" ");
            }
            self.space = false;
        }
        if force == Force::End {
            let abbrs = std::mem::take(&mut self.abbr_list);
            for (abbr, definition) in &abbrs {
                self.emit(&format!("  *[{abbr}]: {definition}\n"));
            }
            self.abbr_list = abbrs;
        }
        self.p_p = 0;
        self.emit(&data);
    }

    fn handle_tag(
        &mut self,
        tag: &str,
        attrs: &[(String, Option<String>)],
        start: bool,
    ) -> Result<(), PyErr> {
        tag.clone_into(&mut self.current_tag);
        if start
            && self.maybe_automatic_link.is_some()
            && !matches!(tag, "p" | "div" | "style" | "dl" | "dt" | "img")
        {
            self.o("[");
            self.maybe_automatic_link = None;
            self.empty_link = false;
        }
        let level = hn(tag);
        if level != 0 {
            if !self.astack.is_empty() {
                if start {
                    if self.out.last().is_some_and(|last| last == "[") {
                        self.out.pop();
                        self.space = false;
                        self.o(&format!("{} ", "#".repeat(level)));
                        self.o("[");
                    }
                } else {
                    self.p_p = 0;
                    return Ok(());
                }
            } else {
                self.p();
                if start {
                    self.o(&format!("{} ", "#".repeat(level)));
                } else {
                    return Ok(());
                }
            }
        }
        if matches!(tag, "p" | "div") && self.astack.is_empty() && !self.split_next_td {
            self.p();
        }
        if tag == "br" && start {
            if self.blockquote > 0 {
                self.o("  \n> ");
            } else {
                self.o("  \n");
            }
        }
        if tag == "hr" && start {
            self.p();
            self.o("* * *");
            self.p();
        }
        if matches!(tag, "head" | "style" | "script") {
            self.quiet += if start { 1 } else { -1 };
        }
        if tag == "body" {
            self.quiet = 0;
        }
        if tag == "blockquote" {
            if start {
                self.p();
                self.output("> ", false, Force::Yes);
                self.start = true;
                self.blockquote += 1;
            } else {
                self.blockquote -= 1;
                self.p();
            }
        }
        if matches!(tag, "em" | "i" | "u") {
            let separate =
                start
                    && self.preceding_data.chars().last().is_some_and(|c| {
                        !" \t\n\r\u{b}\u{c}".contains(c) && !PUNCTUATION.contains(c)
                    });
            if separate {
                self.preceding_data.push(' ');
                self.o(" _");
            } else {
                self.o("_");
            }
            if start {
                self.stressed = true;
            }
        }
        if matches!(tag, "strong" | "b") {
            if start && self.preceding_data.ends_with('*') {
                self.preceding_data.push(' ');
                self.o(" **");
            } else {
                self.o("**");
            }
            if start {
                self.stressed = true;
            }
        }
        if matches!(tag, "del" | "strike" | "s") {
            if start && self.preceding_data.ends_with('~') {
                self.preceding_data.push(' ');
                self.o(" ~~");
            } else {
                self.o("~~");
            }
            if start {
                self.stressed = true;
            }
        }
        if matches!(tag, "kbd" | "code" | "tt") && !self.pre {
            self.o("`");
            self.code = !self.code;
        }
        if tag == "abbr" {
            if start {
                self.abbr_title = None;
                self.abbr_data = Some(String::new());
                if let Some(title) = get_attr(attrs, "title") {
                    self.abbr_title = title.map(str::to_owned);
                }
            } else {
                if let Some(title) = self.abbr_title.take() {
                    let Some(data) = self.abbr_data.clone() else {
                        return Err(PyErr::new("AssertionError", ""));
                    };
                    // a dict: a name defined again keeps its place
                    match self.abbr_list.iter_mut().find(|(name, _)| *name == data) {
                        Some(entry) => entry.1 = title,
                        None => self.abbr_list.push((data, title)),
                    }
                }
                self.abbr_data = None;
            }
        }
        if tag == "q" {
            self.o("\"");
            self.quote = !self.quote;
        }
        if tag == "a" {
            if start {
                match get_attr(attrs, "href") {
                    Some(Some(href)) if !href.starts_with('#') => {
                        let title = get_attr(attrs, "title").flatten().map(str::to_owned);
                        self.astack.push(Some(Anchor {
                            href: href.to_owned(),
                            title,
                        }));
                        self.maybe_automatic_link = Some(href.to_owned());
                        self.empty_link = true;
                    }
                    _ => self.astack.push(None),
                }
            } else if let Some(anchor) = self.astack.pop() {
                if self
                    .maybe_automatic_link
                    .as_deref()
                    .is_some_and(|l| !l.is_empty())
                    && !self.empty_link
                {
                    self.maybe_automatic_link = None;
                } else if let Some(anchor) = anchor {
                    if self.empty_link {
                        self.o("[");
                        self.empty_link = false;
                        self.maybe_automatic_link = None;
                    }
                    self.p_p = 0;
                    let title = escape_md(anchor.title.as_deref().unwrap_or_default());
                    let title = if strip(&title).is_empty() {
                        String::new()
                    } else {
                        format!(" \"{title}\"")
                    };
                    self.o(&format!("]({}{title})", escape_md(&anchor.href)));
                }
            }
        }
        if tag == "img"
            && start
            && let Some(Some(src)) = get_attr(attrs, "src")
        {
            let alt = get_attr(attrs, "alt").flatten().unwrap_or_default();
            if self.maybe_automatic_link.is_some() {
                self.o("[");
                self.maybe_automatic_link = None;
                self.empty_link = false;
            }
            self.o(&format!("![{}]", escape_md(alt)));
            self.o(&format!("({})", escape_md(src)));
        }
        if tag == "dl" && start {
            self.p();
        }
        if tag == "dt" && !start {
            self.pbr();
        }
        if tag == "dd" && start {
            self.o("    ");
        }
        if tag == "dd" && !start {
            self.pbr();
        }
        if matches!(tag, "ol" | "ul") {
            if self.list.is_empty() && !self.last_was_list {
                self.p();
            }
            if start {
                let num = match get_attr(attrs, "start") {
                    Some(None) => return Err(PyErr::new("AssertionError", "")),
                    Some(Some(text)) => parse_start(text).map_or(0, |n| n.saturating_sub(1)),
                    None => 0,
                };
                self.list.push(List {
                    ordered: tag == "ol",
                    num,
                });
            } else if self.list.pop().is_some() && self.list.is_empty() {
                self.o("\n");
            }
            self.last_was_list = true;
        } else {
            self.last_was_list = false;
        }
        if tag == "li" {
            self.list_code_indent.clear();
            self.pbr();
            if start {
                if self.list.is_empty() {
                    // `ListElement("ul", 0)`, thrown away after this item
                    let indent = String::new();
                    self.o(&indent);
                    self.list_code_indent.push_str("  ");
                    self.o("* ");
                } else {
                    let mut parent_ordered = false;
                    let mut indent = String::new();
                    for list in &self.list {
                        indent.push_str(if parent_ordered { "   " } else { "  " });
                        parent_ordered = list.ordered;
                    }
                    self.list_code_indent = indent.clone();
                    self.o(&indent);
                    let last = self.list.len() - 1;
                    if self.list[last].ordered {
                        self.list[last].num += 1;
                        self.list_code_indent.push_str("   ");
                        let number = self.list[last].num;
                        self.o(&format!("{number}. "));
                    } else {
                        self.list_code_indent.push_str("  ");
                        self.o("* ");
                    }
                }
                self.start = true;
            }
        }
        if matches!(tag, "table" | "tr" | "td" | "th") {
            if tag == "table" && start {
                self.table_start = true;
            }
            if matches!(tag, "td" | "th") && start {
                if self.split_next_td {
                    self.o("| ");
                }
                self.split_next_td = true;
            }
            if tag == "tr" && start {
                self.td_count = 0;
            }
            if tag == "tr" && !start {
                self.split_next_td = false;
                self.soft_br();
            }
            if tag == "tr" && !start && self.table_start {
                self.o(&vec!["---"; self.td_count].join("|"));
                self.soft_br();
                self.table_start = false;
            }
            if matches!(tag, "td" | "th") && start {
                self.td_count += 1;
            }
        }
        if tag == "pre" {
            if start {
                self.startpre = true;
                self.pre = true;
            } else {
                self.pre = false;
            }
            self.p();
        }
        Ok(())
    }

    fn handle_data(&mut self, data: &str, entity_char: bool) {
        if data.is_empty() {
            return;
        }
        let mut data = data.to_owned();
        if self.stressed {
            data = strip(&data).to_owned();
            self.stressed = false;
            self.preceding_stressed = true;
        } else if self.preceding_stressed {
            let first = data.chars().next().unwrap_or(' ');
            let word_like = !"][(){}.!?".contains(first) && !is_space(first);
            if word_like
                && hn(&self.current_tag) == 0
                && !matches!(self.current_tag.as_str(), "a" | "code" | "pre")
            {
                data.insert(0, ' ');
            }
            self.preceding_stressed = false;
        }
        if let Some(href) = self.maybe_automatic_link.clone() {
            let absolute = {
                let scheme = href.find("://").map(|at| &href[..at]);
                scheme.is_some_and(|scheme| {
                    !scheme.is_empty()
                        && scheme.chars().all(|c| c.is_ascii_alphabetic() || c == '+')
                })
            };
            if href == data && absolute {
                self.o(&format!("<{data}>"));
                self.empty_link = false;
                return;
            }
            self.o("[");
            self.maybe_automatic_link = None;
            self.empty_link = false;
        }
        if !self.code && !self.pre && !entity_char {
            data = escape_md_section(&data);
        }
        self.preceding_data.clone_from(&data);
        self.output(&data, true, Force::No);
    }

    /// `charref(name)`.
    fn charref(name: &str) -> Result<String, PyErr> {
        let invalid = |base: u32, digits: &str| {
            PyErr::new(
                "ValueError",
                format!(
                    "invalid literal for int() with base {base}: {}",
                    ace_mod_oletools::py::repr_str(digits)
                        .chars()
                        .take(200)
                        .collect::<String>()
                ),
            )
        };
        let code = match name.strip_prefix(['x', 'X']) {
            Some(hex) => {
                if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(invalid(16, hex));
                }
                hex.chars().fold(0_u32, |value, c| {
                    value
                        .saturating_mul(16)
                        .saturating_add(c.to_digit(16).unwrap_or(0))
                })
            }
            None => {
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_digit()) {
                    return Err(invalid(10, name));
                }
                if name.len() > 4300 {
                    return Err(PyErr::new(
                        "ValueError",
                        format!(
                            "Exceeds the limit (4300 digits) for integer string conversion: value \
                             has {} digits; use sys.set_int_max_str_digits() to increase the limit",
                            name.len()
                        ),
                    ));
                }
                name.chars().fold(0_u32, |value, c| {
                    value
                        .saturating_mul(10)
                        .saturating_add(c.to_digit(10).unwrap_or(0))
                })
            }
        };
        let mut code = code;
        if code == 0 || code >= 0x11_0000 || (0xD800..0xE000).contains(&code) {
            code = 0xFFFD;
        }
        if let Some((_, replaced)) = CONTROL_REPLACEMENTS.iter().find(|(from, _)| *from == code) {
            code = *replaced;
        }
        if let Some((_, _, text)) = UNIFIABLE
            .iter()
            .find(|(name, point, _)| *point == code && *name != "nbsp")
        {
            return Ok((*text).to_owned());
        }
        Ok(char::from_u32(code).map(String::from).unwrap_or_default())
    }

    /// `entityref(c)`.
    fn entityref(name: &str) -> String {
        if let Some((_, _, text)) = UNIFIABLE.iter().find(|(key, _, _)| *key == name) {
            return (*text).to_owned();
        }
        match entities::html5(&format!("{name};")) {
            Some(text) => text.to_owned(),
            None => format!("&{name};"),
        }
    }

    fn finish(&mut self) -> String {
        self.pbr();
        self.output("", false, Force::End);
        self.out.concat().replace(NBSP_HOLDER, " ")
    }
}

impl Handler for Html2Text {
    fn start_tag(&mut self, tag: &str, attrs: &[(String, Option<String>)]) -> Result<(), PyErr> {
        self.handle_tag(tag, attrs, true)
    }

    fn end_tag(&mut self, tag: &str) -> Result<(), PyErr> {
        self.handle_tag(tag, &[], false)
    }

    fn char_ref(&mut self, name: &str) -> Result<(), PyErr> {
        let text = Html2Text::charref(name)?;
        self.handle_data(&text, true);
        Ok(())
    }

    fn entity_ref(&mut self, name: &str) -> Result<(), PyErr> {
        let text = Html2Text::entityref(name);
        if !text.is_empty() {
            self.handle_data(&text, true);
        }
        Ok(())
    }

    fn data(&mut self, data: &str) -> Result<(), PyErr> {
        self.handle_data(data, false);
        Ok(())
    }
}

/// `\d+\.\s`, `.match`.
fn is_ordered_item(text: &str) -> bool {
    let mut chars = text.chars().peekable();
    let mut any = false;
    while chars.peek().copied().is_some_and(is_decimal) {
        chars.next();
        any = true;
    }
    any && chars.next() == Some('.') && chars.next().is_some_and(is_space)
}

/// `skipwrap`, on the defaults.
fn skipwrap(para: &str) -> bool {
    if para.starts_with("    ") || para.starts_with('\t') {
        return true;
    }
    let stripped = para.trim_start_matches(is_space);
    let mut chars = stripped.chars();
    let (first, second, third) = (chars.next(), chars.next(), chars.next());
    if first == Some('-') && second == Some('-') && third.is_some_and(|c| c != '-') {
        return false;
    }
    if matches!(first, Some('-' | '*')) && !stripped.starts_with("**") {
        return true;
    }
    if para.contains(" | ") {
        return true;
    }
    is_ordered_item(stripped)
        || (matches!(first, Some('-' | '*' | '+')) && second.is_some_and(is_space))
}

/// `config.RE_SPACE.match(para)`: `\s\+`.
fn re_space(para: &str) -> bool {
    let mut chars = para.chars();
    chars.next().is_some_and(is_space) && chars.next() == Some('+')
}

/// `optwrap`.
fn optwrap(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut newlines = 0;
    for para in text.split('\n') {
        if para.is_empty() {
            if newlines < 2 {
                result.push('\n');
                newlines += 1;
            }
        } else if !skipwrap(para) {
            let indent = if para.starts_with("  *") {
                "    "
            } else if para.starts_with("> ") {
                "> "
            } else {
                ""
            };
            result.push_str(&wrap_with(para, BODY_WIDTH, false, indent).join("\n"));
            if para.ends_with("  ") {
                result.push_str("  \n");
                newlines = 1;
            } else if !indent.is_empty() {
                result.push('\n');
                newlines = 1;
            } else {
                result.push_str("\n\n");
                newlines = 2;
            }
        } else if !re_space(para) {
            result.push_str(para);
            result.push('\n');
            newlines = 1;
        }
    }
    result
}

/// `html2text(html)`. It raises for what `int()` refuses in a reference and for `<ol start>`.
pub fn html2text(html: &str) -> Result<String, PyErr> {
    let html = html.replace("</' + 'script>", "</ignore>");
    let chars: Vec<char> = html.chars().collect();
    let mut state = Html2Text {
        start: true,
        ..Html2Text::default()
    };
    htmlparser::parse(&chars, &mut state)?;
    Ok(optwrap(&state.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_wraps_and_escapes() {
        assert_eq!(html2text("").unwrap(), "\n\n");
        assert_eq!(
            html2text("The password is Secr3tPw").unwrap(),
            "The password is Secr3tPw\n\n"
        );
    }

    #[test]
    fn a_link_keeps_its_url() {
        assert_eq!(
            html2text("<p>see <a href=\"http://x.test/a\">here</a></p>").unwrap(),
            "see [here](http://x.test/a)\n\n"
        );
    }

    #[test]
    fn what_python_raises_raises() {
        assert_eq!(html2text("&#1a").unwrap_err().kind, "ValueError");
        assert_eq!(html2text("<ol start>").unwrap_err().kind, "AssertionError");
    }
}
