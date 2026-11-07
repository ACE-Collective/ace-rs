//! `textwrap.wrap(text, width)` with its default options, which rtfobj's table runs each cell through.

use crate::py::{is_space, is_word};

const WHITESPACE: [char; 6] = ['\t', '\n', '\u{b}', '\u{c}', '\r', ' '];

fn is_ws(c: char) -> bool {
    WHITESPACE.contains(&c)
}

fn is_decimal(c: char) -> bool {
    use std::sync::OnceLock;
    if c.is_ascii() {
        return c.is_ascii_digit();
    }
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"^\p{Nd}$").expect("a valid class"));
    let mut buffer = [0; 4];
    re.is_match(c.encode_utf8(&mut buffer))
}

fn is_letter(c: char) -> bool {
    is_word(c) && !is_decimal(c)
}

fn is_word_punct(c: char) -> bool {
    is_word(c) || matches!(c, '!' | '"' | '\'' | '&' | '.' | ',' | '?')
}

/// `str.expandtabs(8)`.
fn expand_tabs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut column = 0;
    for c in text.chars() {
        match c {
            '\t' => {
                let spaces = 8 - column % 8;
                out.extend(std::iter::repeat_n(' ', spaces));
                column += spaces;
            }
            '\n' | '\r' => {
                out.push(c);
                column = 0;
            }
            c => {
                out.push(c);
                column += 1;
            }
        }
    }
    out
}

/// One match of `wordsep_re` from `start`. It always matches something there: whitespace, or a word
/// that at the very least runs to the next whitespace.
fn next_chunk(text: &[char], start: usize) -> usize {
    let at = |index: isize| -> Option<char> {
        if index < 0 {
            None
        } else {
            text.get(index as usize).copied()
        }
    };
    if is_ws(text[start]) {
        let mut end = start;
        while end < text.len() && is_ws(text[end]) {
            end += 1;
        }
        return end;
    }
    let hyphens_then_word = |from: usize| -> Option<usize> {
        let mut end = from;
        while text.get(end) == Some(&'-') {
            end += 1;
        }
        (end - from >= 2 && text.get(end).is_some_and(|&c| is_word(c))).then_some(end)
    };
    if start > 0
        && is_word_punct(text[start - 1])
        && let Some(end) = hyphens_then_word(start)
    {
        return end;
    }
    // [^ws]+? then a hyphen in a word, the end of a word, or an em-dash
    let mut lazy = start + 1;
    loop {
        if lazy >= text.len() || is_ws(text[lazy]) {
            return lazy;
        }
        let r = lazy as isize;
        if text[lazy] == '-' {
            let after = at(r - 1).is_some_and(is_letter) && at(r - 2).is_some_and(is_letter);
            let or_after = at(r - 1).is_some_and(is_word_punct)
                && at(r - 2) == Some('-')
                && at(r - 3).is_some_and(is_letter);
            if after || or_after {
                let next = at(r + 1);
                let next2 = at(r + 2);
                let next3 = at(r + 3);
                let followed = next.is_some_and(is_letter)
                    && (next2.is_some_and(is_letter)
                        || (next2 == Some('-') && next3.is_some_and(is_letter)));
                if followed {
                    return lazy + 1;
                }
            }
        }
        if at(r - 1).is_some_and(is_word_punct) && hyphens_then_word(lazy).is_some() {
            return lazy;
        }
        lazy += 1;
    }
}

/// `textwrap.wrap(text, width)`.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    wrap_with(text, width, true, "")
}

/// `textwrap.wrap(text, width, break_long_words=..., subsequent_indent=...)`.
pub fn wrap_with(
    text: &str,
    full_width: usize,
    break_long_words: bool,
    subsequent_indent: &str,
) -> Vec<String> {
    let indent_length = subsequent_indent.chars().count();
    let munged: Vec<char> = expand_tabs(text)
        .chars()
        .map(|c| if is_ws(c) { ' ' } else { c })
        .collect();
    let mut chunks: Vec<Vec<char>> = Vec::new();
    let mut start = 0;
    while start < munged.len() {
        let end = next_chunk(&munged, start);
        chunks.push(munged[start..end].to_vec());
        start = end;
    }
    chunks.reverse();
    let blank = |chunk: &[char]| chunk.iter().all(|&c| is_space(c));
    let mut lines = Vec::new();
    while !chunks.is_empty() {
        let mut line: Vec<Vec<char>> = Vec::new();
        let mut length = 0;
        let width = if lines.is_empty() {
            full_width
        } else {
            full_width.saturating_sub(indent_length)
        };
        if !lines.is_empty() {
            chunks.pop_if(|chunk| blank(chunk));
        }
        while let Some(chunk) = chunks.last() {
            if length + chunk.len() <= width {
                length += chunk.len();
                line.push(chunks.pop().expect("there's a last"));
            } else {
                break;
            }
        }
        let too_long = chunks.last().is_some_and(|chunk| chunk.len() > width);
        if too_long && !break_long_words {
            if line.is_empty() {
                line.push(chunks.pop().expect("there's a last"));
            }
        } else if too_long {
            let space_left = if width < 1 { 1 } else { width - length };
            if space_left > 0 {
                let chunk = chunks.last_mut().expect("there's a last");
                let mut end = space_left;
                if chunk.len() > space_left {
                    let hyphen = chunk[..space_left].iter().rposition(|&c| c == '-');
                    if let Some(hyphen) = hyphen
                        && hyphen > 0
                        && chunk[..hyphen].iter().any(|&c| c != '-')
                    {
                        end = hyphen + 1;
                    }
                }
                let rest = chunk.split_off(end);
                line.push(std::mem::replace(chunk, rest));
            } else if line.is_empty() {
                line.push(chunks.pop().expect("there's a last"));
            }
        }
        line.pop_if(|chunk| blank(chunk));
        if !line.is_empty() {
            let indent = if lines.is_empty() {
                ""
            } else {
                subsequent_indent
            };
            lines.push(format!(
                "{indent}{}",
                line.iter().flatten().collect::<String>()
            ));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_as_python_does() {
        assert_eq!(wrap("aaa bbb ccc", 7), ["aaa bbb", "ccc"]);
        assert_eq!(
            wrap("well-known-thing here", 10),
            ["well-", "known-", "thing here"]
        );
        assert_eq!(wrap("abcdefghijkl", 5), ["abcde", "fghij", "kl"]);
        assert!(wrap("", 5).is_empty());
        assert_eq!(wrap("  a", 5), ["  a"]);
    }
}
