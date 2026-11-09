//! Python `re` patterns, as an analyst writes them for ace3's IOC extraction, on fancy-regex.
//!
//! fancy-regex has the lookarounds those patterns use. Where Python's classes differ from Rust's,
//! the pattern is rewritten to Python's: `\w` is a letter, a number or `_` (`[\p{L}\p{N}_]`,
//! which is `str.isalnum() or "_"` for every code point), `\b` and `\B` are boundaries of that
//! `\w`, `\s` adds the four separators `\x1c` to `\x1f` that `str.isspace()` counts, `$` also
//! matches before a final newline, and `\Z` is the end. `\d` is `\p{Nd}` in both. What isn't
//! rewritten: `\W` and `\S` inside a class keep Rust's meaning, and IGNORECASE folds by Unicode's
//! simple case folding, where Python also matches İ and ı to `i`.
//!
//! A `\b` written as lookarounds runs fancy-regex's backtracking machine at every position, which
//! on a large text is many times slower than Python. Rust's own `\w`, `\b` and `\s` differ from
//! Python's only on some characters outside ASCII (combining marks, connector punctuation, the
//! joiners, numbers that aren't digits or letters). So each pattern is compiled twice, with Rust's
//! classes and with Python's, and a text none of whose characters is classed differently uses the
//! first, which gives the same matches.

use fancy_regex::Regex;

const WORD: &str = r"\p{L}\p{N}_";
const SPACE: &str = r"\s\x1c-\x1f";

/// The pattern in fancy-regex's syntax with Python's meaning, keeping Rust's `\w`, `\W`, `\b` and `\B` when `native`.
fn translate(pattern: &str, native: bool) -> String {
    let mut out = String::with_capacity(pattern.len() * 2);
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    let mut class_start = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            let Some(next) = chars.next() else {
                out.push('\\');
                break;
            };
            let replacement = match (in_class, next) {
                (_, 'w' | 'W' | 'b' | 'B') if native => format!("\\{next}"),
                (false, 'w') => format!("[{WORD}]"),
                (false, 'W') => format!("[^{WORD}]"),
                (false, 's') => format!("[{SPACE}]"),
                (false, 'S') => format!("[^{SPACE}]"),
                (false, 'b') => format!("(?:(?<=[{WORD}])(?![{WORD}])|(?<![{WORD}])(?=[{WORD}]))"),
                (false, 'B') => format!("(?:(?<=[{WORD}])(?=[{WORD}])|(?<![{WORD}])(?![{WORD}]))"),
                (false, 'Z') => r"\z".to_owned(),
                (true, 'w') => WORD.to_owned(),
                (true, 's') => SPACE.to_owned(),
                (_, other) => format!("\\{other}"),
            };
            out.push_str(&replacement);
            class_start = false;
            continue;
        }
        if in_class {
            if c == ']' && !class_start {
                in_class = false;
            } else if c == '[' {
                // a literal [ in a class, which Rust reads as a nested class
                out.push_str("\\[");
                class_start = false;
                continue;
            }
            class_start = class_start && c == '^';
            out.push(c);
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                class_start = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    chars.next();
                    out.push('^');
                }
            }
            '$' => out.push_str(r"(?:$|(?=\n\z))"),
            _ => out.push(c),
        }
    }
    out
}

fn build(pattern: &str) -> Result<Regex, String> {
    fancy_regex::RegexBuilder::new(pattern)
        .backtrack_limit(usize::MAX)
        .build()
        .map_err(|e| e.to_string())
}

/// A compiled pattern: with Rust's classes, for a text they class as Python does, and with
/// Python's. Python's `re` has no limit on how far it backtracks, and fancy-regex's default counts a
/// whole search, which a large ordinary text passes with a lookbehind pattern, so the limit is
/// lifted: the task's deadline bounds a pattern instead (docs/measurements/url-extraction.md).
pub struct Pattern {
    native: Regex,
    exact: Regex,
}

impl Pattern {
    /// The regex for `text`: the faster one when `text` has no character Rust classes otherwise.
    pub fn for_text(&self, plain: bool) -> &Regex {
        if plain { &self.native } else { &self.exact }
    }
}

/// `re.compile(pattern)`, or the error that keeps it out.
pub fn compile(pattern: &str) -> Result<Pattern, String> {
    Ok(Pattern {
        native: build(&translate(pattern, true))?,
        exact: build(&translate(pattern, false))?,
    })
}

/// Whether Rust's `\w`, `\s` and `\d` class every character of `text` as Python's do, so a
/// pattern's native form matches as its exact one does.
pub fn classes_agree(text: &str) -> bool {
    use std::sync::LazyLock;
    static WORD: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^\w$").expect("a regex"));
    static SPACE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^[\s\x1c-\x1f]$").expect("a regex"));
    static DIGIT: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^\d$").expect("a regex"));
    if text.is_ascii() {
        return true;
    }
    let mut seen = std::collections::HashSet::new();
    let mut buf = [0u8; 4];
    for c in text.chars().filter(|c| !c.is_ascii()) {
        if !seen.insert(c) {
            continue;
        }
        let s: &str = c.encode_utf8(&mut buf);
        if WORD.is_match(s) != ace_pycompat::pystr::is_word(c)
            || SPACE.is_match(s) != ace_pycompat::pystr::is_space(c)
            || DIGIT.is_match(s) != ace_pycompat::pystr::is_decimal(c)
        {
            return false;
        }
    }
    true
}

/// `pattern.sub(repl, text)`'s template: `\\`, `\n` and the like, `\1` and `\g<name>`.
pub fn expand(repl: &str, caps: &fancy_regex::Captures<'_, str>) -> String {
    if !repl.contains('\\') {
        return repl.to_owned();
    }
    let mut out = String::new();
    let mut chars = repl.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('g') if chars.peek() == Some(&'<') => {
                chars.next();
                let name: String = chars.by_ref().take_while(|c| *c != '>').collect();
                let group = match name.parse::<usize>() {
                    Ok(n) => caps.get(n),
                    Err(_) => caps.name(&name),
                };
                out.push_str(group.map_or("", |m| m.as_str()));
            }
            Some(d) if d.is_ascii_digit() => {
                let mut n = d.to_digit(10).unwrap_or(0) as usize;
                if let Some(&e) = chars.peek()
                    && e.is_ascii_digit()
                {
                    chars.next();
                    n = n * 10 + e.to_digit(10).unwrap_or(0) as usize;
                }
                out.push_str(caps.get(n).map_or("", |m| m.as_str()));
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_classes_and_anchors_are_kept() {
        for plain in [false, true] {
            let word = compile(r"\b\w+\b").unwrap();
            let word = word.for_text(plain);
            assert_eq!(word.find("ünï_9 x").unwrap().unwrap().as_str(), "ünï_9");
            let space = compile(r"a\sb").unwrap();
            assert!(space.for_text(plain).is_match("a\x1cb").unwrap());
            let end = compile(r"^ab$").unwrap();
            assert!(end.for_text(plain).is_match("ab\n").unwrap());
            assert!(!end.for_text(plain).is_match("ab\nc").unwrap());
            let class = compile(r"[\[\(]\s*\.\s*[\]\)]").unwrap();
            assert!(class.for_text(plain).is_match("example[ . ]com").unwrap());
            let ip = compile(r"\b(?<!\d\.)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\.\d)\b").unwrap();
            let found = ip.for_text(plain).find("at 10.1.2.3, not 1.2.3.4.5");
            assert_eq!(found.unwrap().unwrap().as_str(), "10.1.2.3");
        }
        // a combining mark is a word character to Rust and not to Python
        assert!(!classes_agree("e\u{301}"));
        assert!(classes_agree("caf\u{e9} \u{4e2d}"));
        let word = compile(r"\b\w+").unwrap();
        let found = word.for_text(false).find("e\u{301}x");
        assert_eq!(found.unwrap().unwrap().as_str(), "e");
    }
}
