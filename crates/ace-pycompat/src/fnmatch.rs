//! Python's `fnmatch`: `translate`, which turns a shell glob into a regular expression, and
//! `fnmatch`, which matches a name against one as `fnmatch.fnmatch` does on POSIX, where
//! `os.path.normcase` changes nothing, so the match is case-sensitive.

/// `fnmatch.fnmatch(name, pattern)` on POSIX: what the regex `translate` gives would match.
///
/// It matches without compiling that regex. Python caches each compiled pattern; compiling it on
/// every call cost about 20 µs a pattern, and the core checks a declaration's globs for every file
/// it queues, as a parser task, a fresh process, does again. Every token but `*` takes one
/// character, so going back to the last `*` on a mismatch is enough, and a match costs at most the
/// name's length times the pattern's, however many `*`s a pattern has.
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    let (mut p, mut n) = (0, 0);
    // after the last `*`: where its pattern resumes, and where in the name its run ends
    let mut star = None;
    while let Some(c) = name[n..].chars().next() {
        let next = match pattern[p..].chars().next() {
            Some('*') => {
                p += 1;
                star = Some((p, n));
                continue;
            }
            Some('?') => Some(p + 1),
            Some('[') => match set_end(pattern, p) {
                Some(end) => set_matches(&pattern[p + 1..end], c).then_some(end + 1),
                // an unclosed `[` is itself
                None => (c == '[').then_some(p + 1),
            },
            Some(literal) => (literal == c).then_some(p + literal.len_utf8()),
            None => None,
        };
        match (next, star) {
            (Some(next), _) => {
                p = next;
                n += c.len_utf8();
            }
            (None, Some((resume, run_end))) => {
                // the `*` takes one more character and the rest is tried again after it
                let run_end = run_end + name[run_end..].chars().next().map_or(0, char::len_utf8);
                p = resume;
                n = run_end;
                star = Some((resume, run_end));
            }
            (None, None) => return false,
        }
    }
    pattern[p..].bytes().all(|b| b == b'*')
}

/// The `]` closing the set that opens at `open`, found as `translate` finds it: a `]` straight
/// after the `[` or `[!` is a member.
fn set_end(pattern: &str, open: usize) -> Option<usize> {
    let p = pattern.as_bytes();
    let mut j = open + 1;
    if p.get(j) == Some(&b'!') {
        j += 1;
    }
    if p.get(j) == Some(&b']') {
        j += 1;
    }
    p.get(j..)?.iter().position(|&b| b == b']').map(|at| j + at)
}

/// Whether `c` is in a set's text, as `set` reads it: `!` first negates it, `a-z` is a range (a
/// reversed one has no members), and every other character is itself.
fn set_matches(stuff: &str, c: char) -> bool {
    let (negated, body) = match stuff.strip_prefix('!') {
        Some(body) => (true, body),
        None => (false, stuff),
    };
    let mut rest = body.chars();
    let mut member = false;
    while let Some(lo) = rest.next() {
        let mut ahead = rest.clone();
        if ahead.next() == Some('-')
            && let Some(hi) = ahead.next()
        {
            member |= (lo..=hi).contains(&c);
            rest = ahead;
        } else {
            member |= lo == c;
        }
    }
    member != negated
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
    use regex::Regex;

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

    #[test]
    fn sets_read_as_translate_reads_them() {
        // `]` first is a member, and `-` first or last is itself
        assert!(fnmatch("]", "[]]"));
        assert!(!fnmatch("]", "[!]a]"));
        assert!(fnmatch("b", "[!]a]"));
        assert!(fnmatch("-", "[-a]") && fnmatch("-", "[a-]"));
        // an unclosed `[` is itself
        assert!(fnmatch("[a", "[a") && !fnmatch("a", "[a"));
        // a reversed range has no members, and a set left with none matches nothing
        assert!(!fnmatch("m", "[z-a]") && fnmatch("m", "[!z-a]"));
        // after a range, the next `-` starts a member, not a range
        assert!(fnmatch("-", "[a-c-e]") && !fnmatch("d", "[a-c-e]"));
        // a backslash is itself
        assert!(fnmatch("\\", "[\\]") && fnmatch("\\", "\\"));
        // `?` and a set take one character, not one byte
        assert!(fnmatch("é", "?") && fnmatch("é", "[à-ê]") && !fnmatch("é", "[!é]"));
    }

    #[test]
    fn many_stars_on_a_long_name_end() {
        // a backtracking matcher would try every way to split the name among the stars
        let name = "a".repeat(10_000);
        assert!(!fnmatch(&name, "*a*a*a*a*a*a*a*a*a*a*a*a*b"));
        assert!(fnmatch(&name, "*a*a*a*a*a*a*a*a*a*a*a*a*a"));
    }

    /// xorshift64*, so the cases are the same on every run.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 33) as usize % n
        }

        fn string(&mut self, alphabet: &[char], max: usize) -> String {
            let len = self.below(max + 1);
            (0..len)
                .map(|_| alphabet[self.below(alphabet.len())])
                .collect()
        }
    }

    /// A name the pattern may match: each wildcard replaced by something it could stand for.
    fn near_miss(rng: &mut Rng, pattern: &str, alphabet: &[char]) -> String {
        let mut out = String::new();
        for c in pattern.chars() {
            match c {
                '*' => out.push_str(&rng.string(alphabet, 3)),
                '?' | '[' | ']' | '!' | '-' if rng.below(2) == 0 => {
                    out.push(alphabet[rng.below(alphabet.len())]);
                }
                c => out.push(c),
            }
        }
        out
    }

    #[test]
    fn matches_what_the_translated_regex_matches() {
        let pattern_chars: Vec<char> = "*?[]!-/\\.\nabcé".chars().collect();
        let name_chars: Vec<char> = "[]!-/\\.\nabcdé*?".chars().collect();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let (mut cases, mut matched) = (0, 0);
        let mut differ = Vec::new();
        for _ in 0..20_000 {
            let pattern = rng.string(&pattern_chars, 10);
            let Ok(re) = Regex::new(&translate(&pattern)) else {
                panic!("{pattern:?} doesn't compile");
            };
            for k in 0..10 {
                let name = if k < 5 {
                    near_miss(&mut rng, &pattern, &name_chars)
                } else {
                    rng.string(&name_chars, 8)
                };
                let want = re.is_match(&name);
                cases += 1;
                matched += usize::from(want);
                if fnmatch(&name, &pattern) != want && differ.len() < 10 {
                    differ.push(format!("{name:?} against {pattern:?}: regex says {want}"));
                }
            }
        }
        assert!(differ.is_empty(), "{}", differ.join("\n"));
        // both outcomes, often enough that each kind of token is seen deciding a match
        assert!(
            matched > cases / 10 && matched < cases * 9 / 10,
            "{matched} of {cases} matched"
        );
    }
}
