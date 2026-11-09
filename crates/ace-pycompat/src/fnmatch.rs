//! Python's `fnmatch`: `translate`, which turns a shell glob into a regular expression, and
//! `fnmatch`, which matches a name against one as `fnmatch.fnmatch` does on POSIX, where
//! `os.path.normcase` changes nothing, so the match is case-sensitive.

use regex::Regex;

/// `fnmatch.fnmatch(name, pattern)` on POSIX. A pattern that doesn't compile matches nothing.
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    Regex::new(&translate(pattern)).is_ok_and(|re| re.is_match(name))
}

/// `fnmatch.translate(pattern)`: `*` any run, `?` any one character, `[...]` a set (`[!...]`
/// its complement), anything else itself, anchored at both ends, `.` matching a newline.
pub fn translate(pattern: &str) -> String {
    let p: Vec<char> = pattern.chars().collect();
    // fnmatch matches from the start, as `re.match` does
    let mut out = String::from("\\A(?s:");
    let mut i = 0;
    let mut last_star = false;
    while i < p.len() {
        let c = p[i];
        i += 1;
        match c {
            '*' => {
                if !last_star {
                    out.push_str(".*");
                }
                last_star = true;
                continue;
            }
            '?' => out.push('.'),
            '[' => {
                let mut j = i;
                if j < p.len() && p[j] == '!' {
                    j += 1;
                }
                if j < p.len() && p[j] == ']' {
                    j += 1;
                }
                while j < p.len() && p[j] != ']' {
                    j += 1;
                }
                if j >= p.len() {
                    out.push_str("\\[");
                } else {
                    let stuff: Vec<char> = p[i..j].to_vec();
                    i = j + 1;
                    out.push_str(&set(&stuff));
                }
            }
            c => out.push_str(&regex::escape(&c.to_string())),
        }
        last_star = false;
    }
    out.push_str(")\\z");
    out
}

/// A `[...]` set's text as a Rust class: `!` first negates it, `a-z` is a range (a reversed one
/// matches nothing, as Python drops it), and every other character is itself.
fn set(stuff: &[char]) -> String {
    if stuff.is_empty() {
        // an empty set never matches
        return "[^\\s\\S]".to_owned();
    }
    if stuff == ['!'] {
        return ".".to_owned();
    }
    let (negated, body) = if stuff[0] == '!' {
        (true, &stuff[1..])
    } else {
        (false, stuff)
    };
    let escape = |c: char| -> String {
        if c.is_alphanumeric() {
            c.to_string()
        } else {
            format!("\\x{{{:x}}}", c as u32)
        }
    };
    let mut class = String::new();
    let mut k = 0;
    while k < body.len() {
        if k + 2 < body.len() && body[k + 1] == '-' {
            let (lo, hi) = (body[k], body[k + 2]);
            if lo <= hi {
                class.push_str(&format!("{}-{}", escape(lo), escape(hi)));
            }
            k += 3;
        } else {
            class.push_str(&escape(body[k]));
            k += 1;
        }
    }
    if class.is_empty() {
        return if negated {
            ".".to_owned()
        } else {
            "[^\\s\\S]".to_owned()
        };
    }
    format!("[{}{class}]", if negated { "^" } else { "" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_as_fnmatch_does() {
        assert!(fnmatch("/data/a.pcap", "*.pcap"));
        assert!(!fnmatch(
            "/data/email.rfc822.combined",
            "email.rfc822.combined"
        ));
        assert!(fnmatch(
            "a.xlsx.extracted/xl/drawings/d.xml",
            "*/xl/drawings/*"
        ));
        assert!(fnmatch("a\nb", "a*b"));
        assert!(!fnmatch("A.PCAP", "*.pcap"));
        assert!(fnmatch("x1", "x[0-9]"));
        assert!(fnmatch("x!", "x[!a]"));
    }
}
