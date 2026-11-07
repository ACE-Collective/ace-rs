//! Python 3.14's `html.parser.HTMLParser`, with `convert_charrefs=False`, which is how html2text runs it,
//! fed all at once and then closed. The first pass stops at what's incomplete and the closing pass
//! goes on from there with `end` true, reaching the same events as one pass with `end` true, so it
//! makes one. Comments, declarations and processing instructions make no event: html2text ignores them.

use crate::entities;
use ace_mod_oletools::py::{PyErr, strip};

/// What html2text does with the parser's events.
pub trait Handler {
    fn start_tag(&mut self, tag: &str, attrs: &[(String, Option<String>)]) -> Result<(), PyErr>;
    fn end_tag(&mut self, tag: &str) -> Result<(), PyErr>;
    fn char_ref(&mut self, name: &str) -> Result<(), PyErr>;
    fn entity_ref(&mut self, name: &str) -> Result<(), PyErr>;
    fn data(&mut self, data: &str) -> Result<(), PyErr>;
}

/// `[\t\n\r\f ]`.
fn is_html_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{c}' | ' ')
}

/// `[\t\n\r\f />]`'s complement, an attribute name's first character.
fn attr_first(c: char) -> bool {
    !is_html_space(c) && c != '/' && c != '>'
}

/// `[\t\n\r\f /=>]`'s complement.
fn attr_rest(c: char) -> bool {
    attr_first(c) && c != '='
}

fn text(chars: &[char]) -> String {
    chars.iter().collect()
}

struct Parser<'a, H: Handler> {
    raw: &'a [char],
    handler: &'a mut H,
    /// `cdata_elem`, lowercase, and whether references count in it.
    cdata: Option<(String, bool)>,
}

/// One attribute's value: where the group ends, and the value, from the character after `=`.
fn attr_value(raw: &[char], after_equals: usize) -> Option<(usize, String)> {
    let mut at = after_equals;
    while raw.get(at).copied().is_some_and(is_html_space) {
        at += 1;
    }
    let quoted = |at: usize, quote: char| -> Option<usize> {
        if raw.get(at) != Some(&quote) {
            return None;
        }
        let close = raw[at + 1..].iter().position(|&c| c == quote)?;
        Some(at + 1 + close + 1)
    };
    let bare = |at: usize| -> Option<usize> {
        if matches!(raw.get(at), Some('\'' | '"')) {
            return None;
        }
        let mut end = at;
        while raw
            .get(end)
            .copied()
            .is_some_and(|c| c != '>' && !is_html_space(c))
        {
            end += 1;
        }
        Some(end)
    };
    // the whitespace after `=` gives back a character at a time until a value matches
    let mut try_at = at;
    loop {
        if let Some(end) = quoted(try_at, '\'').or_else(|| quoted(try_at, '"')) {
            return Some((end, text(&raw[try_at..end])));
        }
        if let Some(end) = bare(try_at) {
            return Some((end, text(&raw[try_at..end])));
        }
        if try_at == after_equals {
            return None;
        }
        try_at -= 1;
    }
}

/// `[\t\n\r\f ]*=`, from `at`: the position after the `=`.
fn value_indicator(raw: &[char], mut at: usize) -> Option<usize> {
    while raw.get(at).copied().is_some_and(is_html_space) {
        at += 1;
    }
    (raw.get(at) == Some(&'=')).then_some(at + 1)
}

/// `(?<=['"\t\n\r\f /])`.
fn attr_may_start(raw: &[char], at: usize) -> bool {
    at > 0 && (matches!(raw[at - 1], '\'' | '"' | '/') || is_html_space(raw[at - 1]))
}

/// `locatetagend.match(raw, at)`'s end.
fn locate_tag_end(raw: &[char], mut at: usize) -> usize {
    at += 1;
    while raw.get(at).copied().is_some_and(attr_first) {
        at += 1;
    }
    let skip = |at: &mut usize| {
        while raw
            .get(*at)
            .copied()
            .is_some_and(|c| is_html_space(c) || c == '/')
        {
            *at += 1;
        }
    };
    skip(&mut at);
    while attr_may_start(raw, at) && raw.get(at).copied().is_some_and(attr_first) {
        at += 1;
        while raw.get(at).copied().is_some_and(attr_rest) {
            at += 1;
        }
        if let Some(after) = value_indicator(raw, at)
            && let Some((end, _)) = attr_value(raw, after)
        {
            at = end;
        }
        skip(&mut at);
    }
    if raw.get(at) == Some(&'>') {
        at += 1;
    }
    at
}

/// `tagfind_tolerant.match(raw, at)`: the name, and where the match ends.
fn tag_find(raw: &[char], at: usize) -> (String, usize) {
    let mut end = at + 1;
    while raw.get(end).copied().is_some_and(attr_first) {
        end += 1;
    }
    let name = text(&raw[at..end]).to_lowercase();
    (name, skip_tag_space(raw, end))
}

/// `(?:[\t\n\r\f ]|/(?!>))*`.
fn skip_tag_space(raw: &[char], mut at: usize) -> usize {
    loop {
        match raw.get(at) {
            Some(&c) if is_html_space(c) => at += 1,
            Some('/') if raw.get(at + 1) != Some(&'>') => at += 1,
            _ => return at,
        }
    }
}

/// `_unescape_attrvalue`.
fn unescape_attr(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut at = 0;
    while at < chars.len() {
        if chars[at] != '&' {
            out.push(chars[at]);
            at += 1;
            continue;
        }
        let mut end = at + 1;
        let numeric = chars.get(end) == Some(&'#');
        if numeric {
            end += 1;
            let hex = matches!(chars.get(end), Some('x' | 'X'));
            if hex {
                end += 1;
            }
            let start = end;
            while chars.get(end).is_some_and(|c| {
                if hex {
                    c.is_ascii_hexdigit()
                } else {
                    c.is_ascii_digit()
                }
            }) {
                end += 1;
            }
            if end == start {
                out.push('&');
                at += 1;
                continue;
            }
        } else if chars.get(end).is_some_and(char::is_ascii_alphabetic) {
            while chars.get(end).is_some_and(char::is_ascii_alphanumeric) {
                end += 1;
            }
        } else {
            out.push('&');
            at += 1;
            continue;
        }
        let name = text(&chars[at + 1..end]);
        let terminator = chars.get(end).copied().filter(|c| matches!(c, ';' | '='));
        if terminator.is_some() {
            end += 1;
        }
        if numeric {
            let digits = name.trim_start_matches('#');
            out.push_str(&entities::numeric(digits));
            // `html.unescape` takes a `;` with the reference, and an `=` is left as it is
            if terminator == Some('=') {
                out.push('=');
            }
        } else {
            let with = match terminator {
                Some(';') => format!("{name};"),
                _ => name.clone(),
            };
            let known = if terminator == Some('=') {
                None
            } else {
                entities::html5(&with)
            };
            match known {
                Some(value) => out.push_str(value),
                None => out.extend(&chars[at..end]),
            }
        }
        at = end;
    }
    out
}

impl<H: Handler> Parser<'_, H> {
    fn starts_with(&self, at: usize, what: &str) -> bool {
        what.chars()
            .enumerate()
            .all(|(i, c)| self.raw.get(at + i) == Some(&c))
    }

    fn find_char(&self, from: usize, c: char) -> Option<usize> {
        self.raw
            .get(from..)?
            .iter()
            .position(|&x| x == c)
            .map(|p| p + from)
    }

    fn find_str(&self, from: usize, what: &str) -> Option<usize> {
        let what: Vec<char> = what.chars().collect();
        let window = self.raw.get(from..)?;
        window
            .windows(what.len())
            .position(|w| w == &what[..])
            .map(|p| p + from)
    }

    /// `interesting.search(raw, i)`.
    fn interesting(&self, from: usize) -> Option<usize> {
        match &self.cdata {
            None => self.raw[from..]
                .iter()
                .position(|&c| c == '&' || c == '<')
                .map(|p| p + from),
            Some((elem, _)) if elem == "plaintext" => Some(self.raw.len()),
            Some((elem, escapable)) => {
                let elem: Vec<char> = elem.chars().collect();
                let mut at = from;
                while at < self.raw.len() {
                    let c = self.raw[at];
                    if *escapable && c == '&' {
                        return Some(at);
                    }
                    if c == '<' && self.raw.get(at + 1) == Some(&'/') {
                        let name_at = at + 2;
                        let matches = elem.iter().enumerate().all(|(i, e)| {
                            self.raw.get(name_at + i).is_some_and(|c| {
                                // re.IGNORECASE|re.ASCII
                                c.to_ascii_lowercase() == *e
                            })
                        });
                        if matches
                            && self
                                .raw
                                .get(name_at + elem.len())
                                .is_some_and(|&c| is_html_space(c) || c == '/' || c == '>')
                        {
                            return Some(at);
                        }
                    }
                    at += 1;
                }
                None
            }
        }
    }

    fn parse_start_tag(&mut self, i: usize) -> Result<Option<usize>, PyErr> {
        let endpos = locate_tag_end(self.raw, i + 1);
        if self.raw[endpos - 1] != '>' {
            return Ok(None);
        }
        let raw = self.raw;
        let (tag, mut k) = tag_find(raw, i + 1);
        let mut attrs: Vec<(String, Option<String>)> = Vec::new();
        while k < endpos {
            if !attr_may_start(raw, k) || !raw.get(k).copied().is_some_and(attr_first) {
                break;
            }
            let start = k;
            let mut end = k + 1;
            while raw.get(end).copied().is_some_and(attr_rest) {
                end += 1;
            }
            let name = text(&raw[start..end]).to_lowercase();
            let mut value = None;
            if let Some(after) = value_indicator(raw, end)
                && let Some((value_end, found)) = attr_value(raw, after)
            {
                end = value_end;
                let quoted: Vec<char> = found.chars().collect();
                let inner = match (quoted.first(), quoted.last()) {
                    (Some('\''), Some('\'')) | (Some('"'), Some('"')) if quoted.len() >= 2 => {
                        text(&quoted[1..quoted.len() - 1])
                    }
                    // `attrvalue[:1] == q == attrvalue[-1:]` holds for a lone quote too, and its
                    // [1:-1] is empty. A bare value can't start with one, so this is out of caution.
                    _ => found,
                };
                value = Some(if inner.is_empty() {
                    inner
                } else {
                    unescape_attr(&inner)
                });
            }
            attrs.push((name, value));
            k = skip_tag_space(raw, end);
        }
        let rest = text(&raw[k.min(endpos)..endpos]);
        let end = strip(&rest);
        if end != ">" && end != "/>" {
            let whole = text(&raw[i..endpos]);
            self.handler.data(&whole)?;
            return Ok(Some(endpos));
        }
        if end == "/>" {
            self.handler.start_tag(&tag, &attrs)?;
            self.handler.end_tag(&tag)?;
        } else {
            self.handler.start_tag(&tag, &attrs)?;
            match tag.as_str() {
                "script" | "style" | "xmp" | "iframe" | "noembed" | "noframes" | "plaintext" => {
                    self.cdata = Some((tag, false));
                }
                "textarea" | "title" => self.cdata = Some((tag, true)),
                _ => {}
            }
        }
        Ok(Some(endpos))
    }

    fn parse_end_tag(&mut self, i: usize) -> Result<Option<usize>, PyErr> {
        if self.find_char(i + 2, '>').is_none() {
            return Ok(None);
        }
        if !self.raw.get(i + 2).is_some_and(char::is_ascii_alphabetic) {
            if self.raw.get(i + 2) == Some(&'>') {
                return Ok(Some(i + 3));
            }
            return Ok(self.find_char(i + 2, '>').map(|p| p + 1));
        }
        let j = locate_tag_end(self.raw, i + 2);
        if self.raw[j - 1] != '>' {
            return Ok(None);
        }
        let (tag, _) = tag_find(self.raw, i + 2);
        self.handler.end_tag(&tag)?;
        self.cdata = None;
        Ok(Some(j))
    }

    fn parse_comment(&self, i: usize) -> Option<usize> {
        let after = i + 4;
        // commentabruptclose: -?>
        match (self.raw.get(after), self.raw.get(after + 1)) {
            (Some('>'), _) => return Some(after + 1),
            (Some('-'), Some('>')) => return Some(after + 2),
            _ => {}
        }
        let close = self.find_str(after, "--");
        let mut from = close?;
        loop {
            if self.starts_with(from, "-->") {
                return Some(from + 3);
            }
            if self.starts_with(from, "--!>") {
                return Some(from + 4);
            }
            from = self.find_str(from + 1, "--")?;
        }
    }

    fn parse_html_declaration(&self, i: usize) -> Option<usize> {
        if self.starts_with(i, "<![CDATA[") {
            return self.find_str(i + 9, "]]>").map(|j| j + 3);
        }
        let head: String = self.raw[i..self.raw.len().min(i + 9)].iter().collect();
        if head.to_lowercase() == "<!doctype" {
            return self.find_char(i + 9, '>').map(|p| p + 1);
        }
        self.find_char(i + 2, '>').map(|p| p + 1)
    }

    /// `charref.match(raw, i)`: the digits, and the end of the match.
    fn char_ref_match(&self, i: usize) -> Option<(usize, usize)> {
        let start = i + 2;
        let hex = matches!(self.raw.get(start), Some('x' | 'X'));
        let digits_at = if hex { start + 1 } else { start };
        let digit = |c: &char| {
            if hex {
                c.is_ascii_hexdigit()
            } else {
                c.is_ascii_digit()
            }
        };
        let mut end = digits_at;
        while self.raw.get(end).is_some_and(digit) {
            end += 1;
        }
        if end == digits_at {
            return None;
        }
        // [^0-9a-fA-F] must follow, and the digits can't give any back to one
        match self.raw.get(end) {
            Some(c) if !c.is_ascii_hexdigit() => Some((end, end + 1)),
            _ => None,
        }
    }

    /// `entityref.match(raw, i)`: where the name ends and the match. The name's `[-.]` can give one
    /// back to stand as the character after it.
    fn entity_ref_match(&self, i: usize) -> Option<(usize, usize)> {
        let start = i + 1;
        if !self.raw.get(start).is_some_and(char::is_ascii_alphabetic) {
            return None;
        }
        let mut end = start + 1;
        while self
            .raw
            .get(end)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        {
            end += 1;
        }
        loop {
            if self
                .raw
                .get(end)
                .is_some_and(|c| !c.is_ascii_alphanumeric())
            {
                return Some((end, end + 1));
            }
            end -= 1;
            if end == start {
                return None;
            }
        }
    }

    fn go(&mut self) -> Result<(), PyErr> {
        let n = self.raw.len();
        let mut i = 0;
        'outer: while i < n {
            let j = match self.interesting(i) {
                Some(j) => j,
                None if self.cdata.is_some() => break,
                None => n,
            };
            if i < j {
                self.handler.data(&text(&self.raw[i..j]))?;
            }
            i = j;
            if i == n {
                break;
            }
            if self.raw[i] == '<' {
                let next = self.raw.get(i + 1);
                let letter = next.is_some_and(char::is_ascii_alphabetic);
                let found = if letter {
                    self.parse_start_tag(i)?
                } else if self.starts_with(i, "</") {
                    self.parse_end_tag(i)?
                } else if self.starts_with(i, "<!--") {
                    self.parse_comment(i)
                } else if self.starts_with(i, "<?") {
                    self.find_char(i + 2, '>').map(|p| p + 1)
                } else if self.starts_with(i, "<!") {
                    self.parse_html_declaration(i)
                } else {
                    self.handler.data("<")?;
                    Some(i + 1)
                };
                i = match found {
                    Some(k) => k,
                    None => {
                        // what `end` does with something unfinished: it makes no event but this one
                        if self.starts_with(i, "</") && i + 2 == n {
                            self.handler.data("</")?;
                        }
                        n
                    }
                };
            } else if self.starts_with(i, "&#") {
                if let Some((end, whole)) = self.char_ref_match(i) {
                    self.handler.char_ref(&text(&self.raw[i + 2..end]))?;
                    i = if self.raw[whole - 1] == ';' {
                        whole
                    } else {
                        whole - 1
                    };
                    continue 'outer;
                }
                let next = self.raw.get(i + 2);
                let incomplete = next.is_some_and(char::is_ascii_digit)
                    || (matches!(next, Some('x' | 'X'))
                        && self.raw.get(i + 3).is_some_and(char::is_ascii_hexdigit));
                if incomplete {
                    self.handler.char_ref(&text(&self.raw[i + 2..]))?;
                    i = n;
                    break;
                } else if i + 3 < n {
                    self.handler.data("&#")?;
                    i += 2;
                } else {
                    break;
                }
            } else {
                if let Some((end, whole)) = self.entity_ref_match(i) {
                    self.handler.entity_ref(&text(&self.raw[i + 1..end]))?;
                    i = if self.raw[whole - 1] == ';' {
                        whole
                    } else {
                        whole - 1
                    };
                    continue 'outer;
                }
                let incomplete = self
                    .raw
                    .get(i + 1)
                    .is_some_and(|c| c.is_ascii_alphabetic() || *c == '#');
                if incomplete {
                    self.handler.entity_ref(&text(&self.raw[i + 1..]))?;
                    i = n;
                    break;
                } else if i + 1 < n {
                    self.handler.data("&")?;
                    i += 1;
                } else {
                    break;
                }
            }
        }
        if i < n {
            self.handler.data(&text(&self.raw[i..n]))?;
        }
        Ok(())
    }
}

/// Feeds all of `raw` to `handler`, and closes.
pub fn parse<H: Handler>(raw: &[char], handler: &mut H) -> Result<(), PyErr> {
    Parser {
        raw,
        handler,
        cdata: None,
    }
    .go()
}
