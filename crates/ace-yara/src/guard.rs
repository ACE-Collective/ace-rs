//! What a rule file may hold before it reaches yara-x: the bounds that keep a hostile file from taking
//! the process down with it.
//!
//! yara-x 1.22.1 recurses on its input in three places, and none of them checks its stack, so a file
//! deep enough overflows it. That aborts the process: nothing can catch it. A fourth costs time, not
//! stack (`docs/measurements/yara-guard.md` has every number, on stacks of 1, 2, 8 and 64 MiB):
//!
//! - **The lexer** recurses once for each escape sequence in a string or a regex, once for each run of
//!   `*` inside a block comment, and once for each space outside ASCII in a run of spaces. About 2,300
//!   to 2,500 of any of them overflow 2 MiB.
//! - **The parser** is recursive descent, and recurses for each open `(` or `[` and each unary
//!   operator: 384 nested parentheses overflow 2 MiB, or 200 `not` in a row. yara-x's own limit of
//!   3,000 levels is checked later, when the syntax tree is built.
//! - **The compiler** recurses over the tree: 96 nested `pe.sections[...]` overflow 2 MiB.
//! - **Nested calls** cost the parser three times as long for each level, since it tries each
//!   alternative again: 13 levels of `math.abs(` or `uint32(` take a minute, and 20 would take days.
//!
//! [`check`] refuses a source over any bound, with the line and the reason, before the compiler or
//! the parser sees it: the file fails alone, like a file yara-x rejects. Everything that hands rule
//! source to yara-x calls it: the loader (`crate::load`, so the ruleset build, `ace signatures check`,
//! the YARA pool's loader and SVS validation's replay), the parser's use (`crate::source`) and the
//! export of detections (`crate::export`). No thread with a larger stack is used, because SVS's
//! replay is contained to one thread: the bounds are sized for the smallest stack rule source is
//! compiled on, 2 MiB (a thread of the core's runtime), with room to spare. At every bound at once a
//! debug build stays under 1.5 MiB, which the tests run.
//!
//! **How each bound is counted.** The lexer's three are counted on the bytes alone, with no idea of
//! what is a string or a comment, so no crafted file can make this count less than yara-x meets:
//! - Escapes: a string or a regex ends at its line's end, so the escapes of one are at most its line's:
//!   each run of `k` backslashes counts `ceil(k / 2)`. A triple-quoted string spans lines, so a file
//!   that holds `"""` is held to the bound over the whole file.
//! - Comment runs: a block comment ends at the first `*/` after it starts, so its runs are at most
//!   those between the first `/*` after the last `*/` and the next `*/`.
//! - Spaces: the spaces outside ASCII in one run of spaces and tabs.
//!
//! The parser's two need to know which brackets are real, so [`check`] lexes as yara-x's tokenizer
//! does in its normal mode: strings, triple-quoted strings, regexes and comments are skipped, by its
//! own patterns, and a `/` or `"` that starts none of them is the unknown token it makes of the rest
//! of the line. Where the two could differ this counts more, never less: a bracket inside an unknown
//! token opens and never closes. yara-x lexes a hex string in a mode of its own; its brackets are the
//! same tokens, and `?` is taken as its wildcard so `??(01|02)` balances. A `}` returns the count to
//! zero: the parser has unwound there, as it has after any syntax error (measured: two runs of 2,304
//! open parentheses either side of a `}` or a `?` parse, where 2,432 in one run overflow).
//!
//! **Includes.** `include "file"` compiles another file as part of this one, so each file a source
//! includes is checked the same way, wherever yara-x might look for it, to eight levels. yara-x
//! refuses a circular include itself.
//!
//! What a bound refuses that yara-x would compile: a line with more than 1,024 backslash pairs, even
//! in a `//` comment; and a `/*` inside a string followed by more than 1,024 runs of `*` before the
//! next `*/`. Neither is in ace3's rules or in the signatures repository as measured.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// The most escape sequences one string or regex holds. A third of what overflows 2 MiB in a debug
/// build, and what the export of detections has held its own strings to since 7.16.
pub const MAX_ESCAPES: usize = 1024;
/// The most runs of `*` one block comment holds: a comment of 1,024 lines that each start ` * `.
pub const MAX_COMMENT_RUNS: usize = 1024;
/// The most spaces outside ASCII in one run of spaces.
pub const MAX_WIDE_SPACES: usize = 1024;
/// The deepest nesting: open `(` and `[`, and unary operators (`not`, `defined`, `-`, `~`) in a row,
/// counted together. A third of the 96 levels of the costliest construct that overflow 2 MiB.
pub const MAX_NESTING: usize = 32;
/// The deepest nesting of calls, `name(`. Each level triples the parser's time: six cost about 20 ms
/// in a debug build, and eight 180 ms.
pub const MAX_CALL_NESTING: usize = 6;
/// How deep includes may nest, and how many files one source may include in all.
pub const MAX_INCLUDE_DEPTH: usize = 8;
pub const MAX_INCLUDED_FILES: usize = 64;

/// Why a source is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Escapes { line: usize },
    TripleQuotedEscapes,
    CommentRuns { line: usize },
    WideSpaces { line: usize },
    Nesting { line: usize },
    CallNesting { line: usize },
    Include { path: String, reason: String },
    IncludeDepth,
    IncludeCount,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const WHY: &str = "yara-x's parser would overflow its stack";
        match self {
            Refusal::Escapes { line } => write!(
                f,
                "line {line} holds more than {MAX_ESCAPES} escape sequences, and {WHY} on a literal \
                 of that many"
            ),
            Refusal::TripleQuotedEscapes => write!(
                f,
                "the file holds a triple-quoted string and more than {MAX_ESCAPES} escape sequences \
                 in all, and {WHY} on a literal of that many"
            ),
            Refusal::CommentRuns { line } => write!(
                f,
                "the block comment at line {line} holds more than {MAX_COMMENT_RUNS} runs of `*`, \
                 and {WHY}"
            ),
            Refusal::WideSpaces { line } => write!(
                f,
                "line {line} holds a run of more than {MAX_WIDE_SPACES} spaces outside ASCII, and \
                 {WHY}"
            ),
            Refusal::Nesting { line } => write!(
                f,
                "line {line} nests brackets and unary operators more than {MAX_NESTING} deep, and \
                 {WHY}"
            ),
            Refusal::CallNesting { line } => write!(
                f,
                "line {line} nests calls more than {MAX_CALL_NESTING} deep, and each level triples \
                 the time yara-x's parser takes"
            ),
            Refusal::Include { path, reason } => write!(f, "the included file {path}: {reason}"),
            Refusal::IncludeDepth => {
                write!(f, "includes nest more than {MAX_INCLUDE_DEPTH} files deep")
            }
            Refusal::IncludeCount => write!(
                f,
                "the file includes more than {MAX_INCLUDED_FILES} files in all"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Checks one source against every bound. It doesn't follow includes: [`check_file`] does.
pub fn check(source: &[u8]) -> Result<(), Refusal> {
    scan(source).map(|_| ())
}

/// [`check`], and the same for every file the source includes, and theirs. `dirs` are where a
/// relative include is looked for: the including file's directory and the compiler's include
/// directory. yara-x picks one; a file found in either is checked, and one found in neither is left
/// for yara-x to report.
pub fn check_file(source: &[u8], dirs: &[&Path]) -> Result<(), Refusal> {
    let mut seen = BTreeSet::new();
    check_includes(source, dirs, 0, &mut seen)
}

fn check_includes(
    source: &[u8],
    dirs: &[&Path],
    depth: usize,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<(), Refusal> {
    let includes = scan(source)?;
    if includes.is_empty() {
        return Ok(());
    }
    if depth == MAX_INCLUDE_DEPTH {
        return Err(Refusal::IncludeDepth);
    }
    for include in includes {
        let named = Path::new(&include);
        let candidates: Vec<PathBuf> = if named.is_absolute() {
            vec![named.to_path_buf()]
        } else {
            dirs.iter().map(|dir| dir.join(named)).collect()
        };
        for candidate in candidates {
            // a file that can't be read is yara-x's to report
            let Ok(canonical) = candidate.canonicalize() else {
                continue;
            };
            if !seen.insert(canonical.clone()) {
                continue;
            }
            if seen.len() > MAX_INCLUDED_FILES {
                return Err(Refusal::IncludeCount);
            }
            let Ok(included) = std::fs::read(&canonical) else {
                continue;
            };
            let parent = canonical.parent().unwrap_or(Path::new("/")).to_path_buf();
            let mut inner: Vec<&Path> = vec![&parent];
            inner.extend(dirs.iter().copied().filter(|dir| *dir != parent));
            check_includes(&included, &inner, depth + 1, seen).map_err(|reason| match reason {
                Refusal::IncludeDepth | Refusal::IncludeCount | Refusal::Include { .. } => reason,
                other => Refusal::Include {
                    path: include.clone(),
                    reason: other.to_string(),
                },
            })?;
        }
    }
    Ok(())
}

/// Every bound over one source. Returns the files it includes, as written.
fn scan(source: &[u8]) -> Result<Vec<String>, Refusal> {
    lexer_bounds(source)?;
    parser_bounds(source)
}

/// The spaces outside ASCII that yara-x's whitespace token takes, as UTF-8: U+00A0, U+2000 to
/// U+200A, U+202F and U+205F. Returns the length of the one at the start of `bytes`.
fn wide_space(bytes: &[u8]) -> Option<usize> {
    match bytes {
        [0xc2, 0xa0, ..] => Some(2),
        [0xe2, 0x80, 0x80..=0x8a | 0xaf, ..] | [0xe2, 0x81, 0x9f, ..] => Some(3),
        _ => None,
    }
}

/// The lexer's bounds, counted on the bytes alone (the module's docs say why that is enough).
fn lexer_bounds(source: &[u8]) -> Result<(), Refusal> {
    let mut line = 1;
    let mut line_escapes = 0;
    let mut file_escapes = 0;
    let mut triple_quoted = false;
    // the line of the first `/*` since the last `*/`, and the runs of `*` since
    let mut comment: Option<(usize, usize)> = None;
    let mut wide_spaces = 0;

    let mut i = 0;
    while i < source.len() {
        let byte = source[i];
        if let Some(length) = wide_space(&source[i..]) {
            wide_spaces += 1;
            if wide_spaces > MAX_WIDE_SPACES {
                return Err(Refusal::WideSpaces { line });
            }
            i += length;
            continue;
        }
        if byte != b' ' && byte != b'\t' {
            wide_spaces = 0;
        }
        match byte {
            b'\n' => {
                line += 1;
                line_escapes = 0;
                i += 1;
            }
            b'\\' => {
                let run = source[i..].iter().take_while(|b| **b == b'\\').count();
                line_escapes += run.div_ceil(2);
                file_escapes += run.div_ceil(2);
                if line_escapes > MAX_ESCAPES {
                    return Err(Refusal::Escapes { line });
                }
                i += run;
            }
            b'"' => {
                if source[i..].starts_with(b"\"\"\"") {
                    triple_quoted = true;
                }
                i += 1;
            }
            b'/' if comment.is_none() && source.get(i + 1) == Some(&b'*') => {
                comment = Some((line, 0));
                i += 2;
            }
            b'*' => {
                let run = source[i..].iter().take_while(|b| **b == b'*').count();
                i += run;
                if let Some((start, runs)) = &mut comment {
                    if source.get(i) == Some(&b'/') {
                        // the `/` is left where it is: it may open the next comment
                        comment = None;
                    } else {
                        *runs += 1;
                        if *runs > MAX_COMMENT_RUNS {
                            return Err(Refusal::CommentRuns { line: *start });
                        }
                    }
                }
            }
            _ => i += 1,
        }
    }
    if triple_quoted && file_escapes > MAX_ESCAPES {
        return Err(Refusal::TripleQuotedEscapes);
    }
    Ok(())
}

/// What the last token that isn't space or a comment was, for telling a call's `(` and an include's
/// path.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Previous {
    /// A name a call can follow: any word but the keywords an expression in brackets follows.
    Name,
    Include,
    Other,
}

/// The nesting bounds, by lexing as yara-x's tokenizer does in its normal mode.
fn parser_bounds(source: &[u8]) -> Result<Vec<String>, Refusal> {
    let mut includes = Vec::new();
    let mut line = 1;
    // each open bracket: what it adds to the depth (itself and the unary operators before it), and
    // whether it's a call's
    let mut open: Vec<(usize, bool)> = Vec::new();
    let mut depth = 0usize;
    let mut calls = 0usize;
    let mut unary = 0usize;
    let mut previous = Previous::Other;

    let mut i = 0;
    while i < source.len() {
        let byte = source[i];
        let rest = &source[i..];
        // space and comments change nothing
        if matches!(byte, b' ' | b'\t' | b'\r') {
            i += 1;
            continue;
        }
        if byte == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if let Some(length) = wide_space(rest) {
            i += length;
            continue;
        }
        if rest.starts_with(b"//") {
            i += rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
            continue;
        }
        if rest.starts_with(b"/*")
            && let Some(end) = find(&rest[2..], b"*/")
        {
            line += newlines(&rest[..end + 4]);
            i += end + 4;
            continue;
        }

        let mut now = Previous::Other;
        let mut is_unary = false;
        match byte {
            b'(' | b'[' => {
                let call = byte == b'(' && previous == Previous::Name;
                open.push((1 + unary, call));
                depth += 1 + unary;
                calls += usize::from(call);
                if calls > MAX_CALL_NESTING {
                    return Err(Refusal::CallNesting { line });
                }
                i += 1;
            }
            b')' | b']' => {
                if let Some((weight, call)) = open.pop() {
                    depth -= weight;
                    calls -= usize::from(call);
                }
                // what a bracket closed can be called or indexed again, as `a(1)(2)` would be
                now = Previous::Name;
                i += 1;
            }
            b'}' => {
                // the parser has unwound: a hex string or a rule ends here, or it's a syntax error
                open.clear();
                depth = 0;
                calls = 0;
                i += 1;
            }
            b'-' | b'~' => {
                is_unary = true;
                i += 1;
            }
            b'"' => match string_end(rest) {
                Some(end) => {
                    if previous == Previous::Include && !rest.starts_with(b"\"\"\"") {
                        includes.push(String::from_utf8_lossy(&rest[1..end - 1]).into_owned());
                    }
                    line += newlines(&rest[..end]);
                    i += end;
                }
                None => {
                    let end = unknown_end(rest, unterminated_string(rest));
                    opens_in(&rest[..end], &mut open, &mut depth);
                    i += end;
                }
            },
            b'/' => match regex_end(rest) {
                Some(end) => i += end,
                None => {
                    // an unterminated comment runs to the end of the source, a regex to its line's
                    let failed = if rest.starts_with(b"/*") {
                        rest.len()
                    } else {
                        unterminated_regex(rest)
                    };
                    let end = unknown_end(rest, failed);
                    opens_in(&rest[..end], &mut open, &mut depth);
                    line += newlines(&rest[..end]);
                    i += end;
                }
            },
            b'?' => i += 1,
            _ if byte.is_ascii_alphanumeric() || byte == b'_' => {
                let end = rest
                    .iter()
                    .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
                    .unwrap_or(rest.len());
                match &rest[..end] {
                    b"not" | b"defined" => is_unary = true,
                    b"include" => now = Previous::Include,
                    // an expression in brackets follows these: it isn't a call
                    b"and" | b"or" | b"in" | b"of" | b"at" | b"for" | b"contains"
                    | b"icontains" | b"startswith" | b"istartswith" | b"endswith"
                    | b"iendswith" | b"iequals" | b"matches" | b"condition" | b"with" => {}
                    _ => now = Previous::Name,
                }
                i += end;
            }
            // the rest of yara-x's one-byte tokens, and the starts of its pattern identifiers
            b'{' | b'<' | b'>' | b'=' | b'!' | b'&' | b'*' | b'\\' | b':' | b',' | b'.' | b'+'
            | b'%' | b'|' | b'^' | b'$' | b'#' | b'@' => i += 1,
            _ => {
                // not the start of any token: yara-x makes one unknown token of what follows, to
                // the next space
                let end = unknown_end(rest, 1);
                opens_in(&rest[..end], &mut open, &mut depth);
                i += end;
            }
        }

        if is_unary {
            unary += 1;
        } else {
            unary = 0;
        }
        if depth + unary > MAX_NESTING {
            return Err(Refusal::Nesting { line });
        }
        previous = now;
    }
    Ok(includes)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|b| **b == b'\n').count()
}

/// Counts each `(` and `[` of an unknown token as open, and none of its closes: whatever yara-x made
/// of them, it nests no deeper than this.
fn opens_in(token: &[u8], open: &mut Vec<(usize, bool)>, depth: &mut usize) {
    for byte in token {
        if matches!(byte, b'(' | b'[') {
            open.push((1, false));
            *depth += 1;
        }
    }
}

/// Where the string that starts `rest` ends, as yara-x's two string tokens match: the longer of a
/// triple-quoted string, which may span lines and holds no quote, and a string on one line.
fn string_end(rest: &[u8]) -> Option<usize> {
    if rest.starts_with(b"\"\"\"")
        && let Some(end) = string_body(&rest[3..], true)
        && rest[3 + end..].starts_with(b"\"\"\"")
    {
        return Some(end + 6);
    }
    let end = string_body(&rest[1..], false)?;
    Some(end + 2)
}

/// The length of a string's body: escapes, and anything but a quote, a backslash and, on one line, a
/// newline. None when it doesn't reach a quote.
fn string_body(body: &[u8], lines: bool) -> Option<usize> {
    let mut i = 0;
    loop {
        match body.get(i)? {
            b'"' => return Some(i),
            b'\n' if !lines => return None,
            b'\\' => {
                if matches!(body.get(i + 1), None | Some(b'\n')) {
                    return None;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
}

/// How far yara-x's string token reads before it fails: to the line's end, or to a backslash with
/// nothing to escape.
fn unterminated_string(rest: &[u8]) -> usize {
    let mut i = 1;
    loop {
        match rest.get(i) {
            None | Some(b'\n') => return i,
            Some(b'\\') => {
                if matches!(rest.get(i + 1), None | Some(b'\n')) {
                    return i;
                }
                i += 2;
            }
            Some(_) => i += 1,
        }
    }
}

/// Where the regex that starts `rest` ends, with up to two letters after it, as yara-x's token: its
/// first character isn't `*` or `/`, and it closes on its line.
fn regex_end(rest: &[u8]) -> Option<usize> {
    if matches!(rest.get(1), None | Some(b'*' | b'/' | b'\n')) {
        return None;
    }
    let mut i = 1;
    loop {
        match rest.get(i)? {
            b'/' => break,
            b'\n' => return None,
            b'\\' => {
                if matches!(rest.get(i + 1), None | Some(b'\n')) {
                    return None;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    i += 1;
    let modifiers = rest[i..]
        .iter()
        .take(2)
        .take_while(|b| b.is_ascii_alphabetic())
        .count();
    Some(i + modifiers)
}

/// How far yara-x's regex token reads before it fails.
fn unterminated_regex(rest: &[u8]) -> usize {
    unterminated_string(rest)
}

/// Where the unknown token that starts `rest` ends: yara-x takes what its failed token read
/// (`failed`), or the valid UTF-8 up to the next space if that is longer, and at least one byte.
fn unknown_end(rest: &[u8], failed: usize) -> usize {
    let valid = match std::str::from_utf8(rest) {
        Ok(text) => text,
        Err(error) => {
            std::str::from_utf8(&rest[..error.valid_up_to()]).expect("valid up to the error")
        }
    };
    let word = valid.split(char::is_whitespace).next().unwrap_or_default();
    failed.max(word.len()).max(1).min(rest.len())
}

#[cfg(test)]
mod tests;
