//! The parts of Python and of ace3's helpers these modules need that `ace-pycompat` doesn't have:
//! `shlex.split(s, posix=False)`, `ntpath.basename`, ace3's `is_nt_path`,
//! `find_nt_paths_in_text`, `is_base64` and `decode_base64`, and `urlencode`.
//!
//! Python's `re` reads `$` as the end, or just before a newline that ends the string, and `.` as
//! anything but a newline; the matchers here do the same.

use ace_pycompat::PyErr;
use ace_pycompat::parse::quote;
use ace_pycompat::pystr;

/// The text a `$` may end before: all of it, less one newline at its end.
pub fn before_final_newline(s: &str) -> &str {
    s.strip_suffix('\n').unwrap_or(s)
}

/// `shlex.split(s, posix=False)`: words split on space, tab, CR and LF, and a word that starts
/// with a quote runs to the same quote, which it keeps. A quote inside a word is part of it. An
/// unclosed quote raises `ValueError("No closing quotation")`.
pub fn shlex_split_nonposix(s: &str) -> Result<Vec<String>, PyErr> {
    const WHITESPACE: [char; 4] = [' ', '\t', '\r', '\n'];
    let mut tokens = Vec::new();
    let mut chars = s.chars();
    loop {
        // state ' ': skip whitespace, then start a quoted or a plain word
        let first = loop {
            match chars.next() {
                None => return Ok(tokens),
                Some(c) if WHITESPACE.contains(&c) => continue,
                Some(c) => break c,
            }
        };
        let mut token = String::from(first);
        if first == '"' || first == '\'' {
            loop {
                match chars.next() {
                    None => return Err(PyErr::value_error("No closing quotation")),
                    Some(c) => {
                        token.push(c);
                        if c == first {
                            break;
                        }
                    }
                }
            }
        } else {
            loop {
                match chars.next() {
                    None => {
                        tokens.push(token);
                        return Ok(tokens);
                    }
                    Some(c) if WHITESPACE.contains(&c) => break,
                    Some(c) => token.push(c),
                }
            }
        }
        tokens.push(token);
    }
}

/// `ntpath.splitroot(p)`'s drive and root, by their length in characters.
fn ntpath_root_len(p: &[char]) -> usize {
    let norm = |c: char| if c == '/' { '\\' } else { c };
    let at = |i: usize| p.get(i).map(|&c| norm(c));
    if at(0) == Some('\\') {
        if at(1) == Some('\\') {
            let upper: String = p.iter().take(8).map(|&c| norm(c)).collect();
            let start = if pystr::upper(&upper) == "\\\\?\\UNC\\" {
                8
            } else {
                2
            };
            let find = |from: usize| (from..p.len()).find(|&i| at(i) == Some('\\'));
            let Some(index) = find(start) else {
                return p.len();
            };
            let Some(index2) = find(index + 1) else {
                return p.len();
            };
            index2 + 1
        } else {
            1
        }
    } else if at(1) == Some(':') {
        if at(2) == Some('\\') { 3 } else { 2 }
    } else {
        0
    }
}

/// `ntpath.basename(p)`: what follows the last `\` or `/` after the drive and root.
pub fn ntpath_basename(p: &str) -> String {
    let chars: Vec<char> = p.chars().collect();
    let rest = &chars[ntpath_root_len(&chars)..];
    let start = rest
        .iter()
        .rposition(|&c| c == '\\' || c == '/')
        .map_or(0, |i| i + 1);
    rest[start..].iter().collect()
}

/// `.+$`: at least one character, no newline but one that ends the text.
fn dot_plus_to_end(s: &[char]) -> bool {
    let body = match s.last() {
        Some('\n') => &s[..s.len() - 1],
        _ => s,
    };
    !body.is_empty() && !body.contains(&'\n')
}

/// ace3's `is_nt_path` (`saq/util/filesystem.py`): a drive letter path (`^[a-zA-Z]:.+$`) or a UNC
/// path (`^\\\\[^\\]+\\.+$`), with none of `<>:"/|?*` after the drive. Its character class is
/// written in a plain string, `'[<>:"/\\|?*]'`, so a backslash isn't one of them.
pub fn is_nt_path(path: &str) -> bool {
    let chars: Vec<char> = path.chars().collect();
    let drive_letter = chars.len() >= 2
        && chars[0].is_ascii_alphabetic()
        && chars[1] == ':'
        && dot_plus_to_end(&chars[2..]);
    let unc = !drive_letter && chars.len() >= 2 && chars[0] == '\\' && chars[1] == '\\' && {
        let server_end = (2..chars.len()).find(|&i| chars[i] == '\\');
        server_end.is_some_and(|end| end > 2 && dot_plus_to_end(&chars[end + 1..]))
    };
    if !drive_letter && !unc {
        return false;
    }
    let target = if drive_letter {
        &chars[2..]
    } else {
        &chars[..]
    };
    !target
        .iter()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '/' | '|' | '?' | '*'))
}

/// One of `find_nt_paths_in_text`'s four patterns, tried at `i`: the group's range and where the
/// match ends.
fn nt_path_match(
    chars: &[char],
    i: usize,
    escaped: bool,
    unc: bool,
) -> Option<(usize, usize, usize)> {
    // the opening quote: \" or a " with no backslash before it
    let start = if escaped {
        (chars.get(i) == Some(&'\\') && chars.get(i + 1) == Some(&'"')).then_some(i + 2)?
    } else {
        (chars.get(i) == Some(&'"') && (i == 0 || chars[i - 1] != '\\')).then_some(i + 1)?
    };
    // what the group must start with: [a-zA-Z]: or \\[^\\]+\
    let body = if unc {
        if chars.get(start) != Some(&'\\') || chars.get(start + 1) != Some(&'\\') {
            return None;
        }
        let server = start + 2;
        let end = (server..chars.len()).find(|&j| chars[j] == '\\')?;
        if end == server {
            return None;
        }
        end + 1
    } else {
        let letter = chars.get(start).is_some_and(char::is_ascii_alphabetic);
        if !letter || chars.get(start + 1) != Some(&':') {
            return None;
        }
        start + 2
    };
    // [^"]*? up to the closing quote: the next ", which must (\") or mustn't have a backslash
    // before it
    let quote = (body..chars.len()).find(|&j| chars[j] == '"')?;
    if escaped {
        if quote == 0 || quote - 1 < body || chars[quote - 1] != '\\' {
            return None;
        }
        Some((start, quote - 1, quote + 1))
    } else {
        if chars[quote - 1] == '\\' {
            return None;
        }
        Some((start, quote, quote + 1))
    }
}

/// ace3's `find_nt_paths_in_text`: the Windows paths between quotes, escaped (`\"...\"`) or not,
/// that `is_nt_path` accepts, in the order of its four patterns, each once.
pub fn find_nt_paths_in_text(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut paths: Vec<String> = Vec::new();
    for (escaped, unc) in [(true, false), (true, true), (false, false), (false, true)] {
        let mut i = 0;
        while i < chars.len() {
            match nt_path_match(&chars, i, escaped, unc) {
                Some((start, end, next)) => {
                    let path: String = chars[start..end].iter().collect();
                    if !paths.contains(&path) && is_nt_path(&path) {
                        paths.push(path);
                    }
                    i = next;
                }
                None => i += 1,
            }
        }
    }
    paths
}

fn padded(trimmed: &str) -> String {
    let missing = trimmed.chars().count() % 4;
    let mut value = trimmed.to_owned();
    if missing != 0 {
        value.push_str(&"=".repeat(4 - missing));
    }
    value
}

/// ace3's `is_base64` (`saq/util/strings.py`): only base64 characters, either alphabet, that
/// decode once padded, URL-safe or standard.
pub fn is_base64(value: &str) -> bool {
    let trimmed = pystr::strip(value);
    if trimmed.is_empty() {
        return false;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
    {
        return false;
    }
    let test_value = padded(trimmed);
    ace_pycompat::base64::urlsafe_b64decode(&test_value).is_ok()
        || ace_pycompat::base64::b64decode(&test_value).is_ok()
}

/// ace3's `decode_base64`: stripped, padded and decoded URL-safe.
pub fn decode_base64(value: &str) -> Result<Vec<u8>, PyErr> {
    ace_pycompat::base64::urlsafe_b64decode(&padded(pystr::strip(value)))
}

/// `urllib.parse.quote_plus(s)`.
pub fn quote_plus(s: &str) -> String {
    if s.contains(' ') {
        quote(s, " ").replace(' ', "+")
    } else {
        quote(s, "")
    }
}

/// `urllib.parse.urlencode(query, doseq=True)` of a dict of lists of str.
pub fn urlencode_doseq(query: &[(String, Vec<String>)]) -> String {
    let mut parts = Vec::new();
    for (key, values) in query {
        for value in values {
            parts.push(format!("{}={}", quote_plus(key), quote_plus(value)));
        }
    }
    parts.join("&")
}

/// `urllib.parse.urlencode(query)` of a dict of str.
pub fn urlencode(query: &[(&str, &str)]) -> String {
    query
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `saq.util.strings.format_item_list_for_summary` with its default of 20.
pub fn format_item_list_for_summary(items: &[String]) -> String {
    ace_mod_urls::url_extraction::format_item_list_for_summary(items, 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shlex_keeps_quotes_and_splits_on_whitespace_only() {
        assert_eq!(
            shlex_split_nonposix(r#"a "b c" d"e f'g "" 'h'"#).expect("splits"),
            ["a", "\"b c\"", "d\"e", "f'g", "\"\"", "'h'"]
        );
        // a quoted word ends at its quote, and the next starts there
        assert_eq!(
            shlex_split_nonposix(r#""a"b"#).expect("splits"),
            ["\"a\"", "b"]
        );
        assert!(shlex_split_nonposix("a \"b").is_err());
        assert!(shlex_split_nonposix("a b'c").is_ok());
        assert_eq!(
            shlex_split_nonposix(" \t\n").expect("splits"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn basename_is_ntpaths() {
        assert_eq!(ntpath_basename(r"C:\Windows\pwsh.exe"), "pwsh.exe");
        assert_eq!(ntpath_basename("/usr/bin/pwsh"), "pwsh");
        assert_eq!(ntpath_basename("C:pwsh"), "pwsh");
        assert_eq!(ntpath_basename(r"\\server\pwsh"), "");
        assert_eq!(ntpath_basename(r"\\server\share\pwsh"), "pwsh");
        assert_eq!(ntpath_basename("dir/"), "");
    }

    #[test]
    fn nt_paths() {
        assert!(is_nt_path(r"C:\x"));
        assert!(is_nt_path("C:\\x\n"));
        assert!(!is_nt_path("C:\\x\ny"));
        assert!(!is_nt_path("C:"));
        assert!(!is_nt_path(r"C:\x:y"));
        assert!(is_nt_path(r"\\srv\share"));
        assert!(!is_nt_path(r"\\srv"));
        assert!(!is_nt_path(r"\\\share"));
        assert!(!is_nt_path(r"\\srv\a|b"));
        assert_eq!(
            find_nt_paths_in_text(r#"x \"C:\a b\c.exe\" "D:\e f" "\\s\t u" \"\\v\w\""#),
            [r"C:\a b\c.exe", r"\\v\w", r"D:\e f", r"\\s\t u"]
        );
    }

    #[test]
    fn base64() {
        assert!(is_base64("QUJD"));
        assert!(is_base64("QUJ"));
        assert!(!is_base64("Q"));
        assert!(!is_base64("QU JD"));
        assert_eq!(decode_base64("QUJ").expect("decodes"), b"AB");
        assert_eq!(quote_plus("a b&c"), "a+b%26c");
    }
}
