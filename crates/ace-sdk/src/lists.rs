//! Analyst-edited lists (PLAN.md 5.14, ace3 #1063, #1064): whitelists and the like, which live in
//! Postgres behind the API rather than in a file a module watches.
//!
//! A module names the lists it reads in `Module::LISTS`, each a `ListSpec`. The lists a binary knows
//! are the ones its modules read, so a site's module brings its own. An analyst edits a list's
//! entries through the service, which checks each one here before it's stored (`Entry::check`). The
//! core adds the lists a module reads to each of its leased tasks, as of the moment it hands the task
//! out (`wire::LeasedTask::lists`), since a worker holds no database credentials, and the module reads
//! them with `TaskContext::list`.
//!
//! An entry is typed: it matches a value exactly, as a substring, or by a regular expression, with or
//! without case, and on a list whose spec says so it names an observable type too. ace3's
//! `saq/whitelist.py` matched its `smtp_from` and `smtp_to` keys as case-blind substrings, and its site
//! tagger's CSV has the same shape with more kinds of match (7.6 adds those it needs).
//!
//! A pattern is compiled with the `regex` crate, whose matching is linear in the input, so a hostile or
//! mistaken one can't make matching slow; what remains is its size, which is bounded twice. Each
//! pattern alone is at most `MAX_PATTERN_BYTES` and has to compile within `REGEX_SIZE_LIMIT`, and all of
//! one list's patterns, compiled together as the module compiles them, have to fit `LIST_REGEX_LIMIT`.
//! The service checks both before a write commits, so a list a module receives always compiles. A list
//! holds at most `MAX_ENTRIES` entries, which bounds what each leased task carries.

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use regex::{RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};

/// The most entries one list holds.
pub const MAX_ENTRIES: usize = 1000;
/// The longest value of an exact or substring entry, in bytes: ace3's limit on an observable detection.
pub const MAX_VALUE_BYTES: usize = 4096;
/// The longest pattern, in bytes.
pub const MAX_PATTERN_BYTES: usize = 1024;
/// What one pattern may compile to, as `regex`'s `size_limit`. A Unicode `\w` costs about 50 KiB, so
/// `\w{10}` fits and `\w{100}` doesn't; `(?-u)\w` is ASCII and costs a fiftieth of that.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// What all of one list's patterns may compile to together, and the lazy DFA's cache for them.
pub const LIST_REGEX_LIMIT: usize = 8 << 20;
/// The longest note on an entry, in characters.
pub const MAX_NOTE_CHARS: usize = 1024;

/// A list a module reads, as it declares it in `Module::LISTS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListSpec {
    /// Lowercase ASCII letters, digits and `_`, as the API names it.
    pub name: &'static str,
    /// What the list is for, and what its entries are matched against.
    pub description: &'static str,
    /// Each entry names an observable type and matches only observables of it.
    pub typed: bool,
}

impl ListSpec {
    /// Whether `name` is one a list can have.
    pub fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }
}

/// How an entry matches a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// The whole value.
    Exact,
    /// Anywhere in the value, as ace3's whitelist's `item in value`.
    Substring,
    /// A regular expression found anywhere in the value, in the `regex` crate's syntax.
    Regex,
}

impl MatchKind {
    pub const ALL: [MatchKind; 3] = [MatchKind::Exact, MatchKind::Substring, MatchKind::Regex];

    pub fn as_str(self) -> &'static str {
        match self {
            MatchKind::Exact => "exact",
            MatchKind::Substring => "substring",
            MatchKind::Regex => "regex",
        }
    }

    pub fn parse(text: &str) -> Option<MatchKind> {
        MatchKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == text)
    }
}

/// One entry, as a leased task carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: i64,
    #[serde(rename = "match")]
    pub kind: MatchKind,
    /// The value, or the pattern.
    pub value: String,
    pub ignore_case: bool,
    /// On a typed list, the observable type it applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observable_type: Option<String>,
    /// After this it matches nothing. The core still sends it until it's deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Why an entry can't be stored.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidEntry {
    #[error("an entry's value can't be empty")]
    Empty,
    #[error("an entry's value can't hold a NUL character")]
    Nul,
    #[error("a {kind} entry's value is at most {limit} bytes")]
    TooLong { kind: &'static str, limit: usize },
    #[error("the pattern doesn't compile: {0}")]
    Pattern(String),
    #[error(
        "the pattern compiles to more than {REGEX_SIZE_LIMIT} bytes; make it simpler, such as with fewer repetitions or narrower classes"
    )]
    PatternTooLarge,
    #[error(
        "the list's patterns would compile to more than {LIST_REGEX_LIMIT} bytes together; remove or simplify some"
    )]
    ListPatternsTooLarge,
    #[error("a list holds at most {MAX_ENTRIES} entries")]
    TooMany,
    #[error("an entry on list {0} has to name an observable type")]
    NeedsType(String),
    #[error("list {0} doesn't take an observable type")]
    TakesNoType(String),
}

impl Entry {
    /// Checks one entry on `spec`'s list, without its list: its value, and for a pattern that it
    /// compiles alone within `REGEX_SIZE_LIMIT`. `List::check` checks a whole list.
    pub fn check(&self, spec: &ListSpec) -> Result<(), InvalidEntry> {
        if self.value.is_empty() {
            return Err(InvalidEntry::Empty);
        }
        if self.value.contains('\0') {
            return Err(InvalidEntry::Nul);
        }
        match (spec.typed, &self.observable_type) {
            (true, None) => return Err(InvalidEntry::NeedsType(spec.name.to_owned())),
            (false, Some(_)) => return Err(InvalidEntry::TakesNoType(spec.name.to_owned())),
            _ => {}
        }
        let limit = match self.kind {
            MatchKind::Regex => MAX_PATTERN_BYTES,
            MatchKind::Exact | MatchKind::Substring => MAX_VALUE_BYTES,
        };
        if self.value.len() > limit {
            return Err(InvalidEntry::TooLong {
                kind: self.kind.as_str(),
                limit,
            });
        }
        if self.kind == MatchKind::Regex {
            RegexBuilder::new(&self.value)
                .case_insensitive(self.ignore_case)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|error| match error {
                    regex::Error::CompiledTooBig(_) => InvalidEntry::PatternTooLarge,
                    error => InvalidEntry::Pattern(error.to_string()),
                })?;
        }
        Ok(())
    }

    /// The pattern as one of a list's set: its own case rule, in a group of its own. Only a pattern
    /// that compiled alone goes in, so the group can't change what it means.
    fn set_pattern(&self) -> String {
        let flags = if self.ignore_case { "(?i:" } else { "(?:" };
        format!("{flags}{})", self.value)
    }

    fn live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expires| expires > now)
    }
}

/// A list as a leased task carries it: the entries as of the list's version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireList {
    pub name: String,
    /// The lists' version when the core read them. Every committed edit to any list raises it.
    pub version: i64,
    pub entries: Vec<Entry>,
}

/// An exact or substring entry, ready to compare.
#[derive(Debug)]
struct Literal {
    index: usize,
    kind: MatchKind,
    /// Lowercased when the entry ignores case.
    value: String,
    ignore_case: bool,
}

/// A list a module reads, with its patterns compiled the first time it's matched.
#[derive(Debug)]
pub struct List {
    name: String,
    version: i64,
    entries: Vec<Entry>,
    compiled: OnceLock<Result<Compiled, InvalidEntry>>,
}

#[derive(Debug)]
struct Compiled {
    literals: Vec<Literal>,
    /// The regex entries' indexes, in the set's order.
    patterns: Vec<usize>,
    set: Option<RegexSet>,
}

impl List {
    pub fn new(name: impl Into<String>, version: i64, entries: Vec<Entry>) -> List {
        List {
            name: name.into(),
            version,
            entries,
            compiled: OnceLock::new(),
        }
    }

    /// An empty list, as a list with no entries is.
    pub fn empty(name: impl Into<String>) -> List {
        List::new(name, 0, Vec::new())
    }

    pub fn from_wire(list: WireList) -> List {
        List::new(list.name, list.version, list.entries)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> i64 {
        self.version
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Checks a whole list as `spec`'s, as the service does before a write commits: each entry,
    /// the count, and that its patterns compile together within `LIST_REGEX_LIMIT`.
    pub fn check(spec: &ListSpec, entries: &[Entry]) -> Result<(), InvalidEntry> {
        for entry in entries {
            entry.check(spec)?;
        }
        compile(entries).map(|_| ())
    }

    /// The first entry that matches `value`, live at `now`. On a typed list only entries of
    /// `observable_type` are looked at, and on an untyped one it's ignored.
    pub fn find(
        &self,
        observable_type: Option<&str>,
        value: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<&Entry>, InvalidEntry> {
        let compiled = self
            .compiled
            .get_or_init(|| compile(&self.entries))
            .as_ref()
            .map_err(Clone::clone)?;
        let applies = |entry: &Entry| {
            entry.live_at(now)
                && match (&entry.observable_type, observable_type) {
                    (None, _) => true,
                    (Some(wanted), Some(kind)) => wanted == kind,
                    (Some(_), None) => false,
                }
        };
        let lowered = value.to_lowercase();
        let mut found: Option<usize> = None;
        for literal in &compiled.literals {
            let against = if literal.ignore_case { &lowered } else { value };
            let hit = match literal.kind {
                MatchKind::Exact => *against == literal.value,
                _ => against.contains(literal.value.as_str()),
            };
            if hit && applies(&self.entries[literal.index]) {
                found = Some(literal.index);
                break;
            }
        }
        if let Some(set) = &compiled.set {
            for matched in set.matches(value).iter() {
                let index = compiled.patterns[matched];
                if found.is_some_and(|first| first < index) {
                    break;
                }
                if applies(&self.entries[index]) {
                    found = Some(index);
                    break;
                }
            }
        }
        Ok(found.map(|index| &self.entries[index]))
    }
}

fn compile(entries: &[Entry]) -> Result<Compiled, InvalidEntry> {
    if entries.len() > MAX_ENTRIES {
        return Err(InvalidEntry::TooMany);
    }
    let mut literals = Vec::new();
    let mut patterns = Vec::new();
    let mut sources = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        match entry.kind {
            MatchKind::Regex => {
                patterns.push(index);
                sources.push(entry.set_pattern());
            }
            kind => literals.push(Literal {
                index,
                kind,
                value: if entry.ignore_case {
                    entry.value.to_lowercase()
                } else {
                    entry.value.clone()
                },
                ignore_case: entry.ignore_case,
            }),
        }
    }
    let set = if sources.is_empty() {
        None
    } else {
        Some(
            RegexSetBuilder::new(&sources)
                .size_limit(LIST_REGEX_LIMIT)
                .dfa_size_limit(LIST_REGEX_LIMIT)
                .build()
                .map_err(|error| match error {
                    regex::Error::CompiledTooBig(_) => InvalidEntry::ListPatternsTooLarge,
                    error => InvalidEntry::Pattern(error.to_string()),
                })?,
        )
    };
    Ok(Compiled {
        literals,
        patterns,
        set,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: ListSpec = ListSpec {
        name: "test_list",
        description: "a list for tests",
        typed: false,
    };

    const TYPED: ListSpec = ListSpec {
        name: "typed_list",
        description: "a typed list for tests",
        typed: true,
    };

    fn entry(id: i64, kind: MatchKind, value: &str, ignore_case: bool) -> Entry {
        Entry {
            id,
            kind,
            value: value.to_owned(),
            ignore_case,
            observable_type: None,
            expires_at: None,
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-01-01T00:00:00Z".parse().expect("a time")
    }

    fn found(list: &List, value: &str) -> Option<i64> {
        list.find(None, value, now())
            .expect("compiles")
            .map(|e| e.id)
    }

    #[test]
    fn each_kind_matches_as_it_says() {
        let list = List::new(
            "test_list",
            1,
            vec![
                entry(1, MatchKind::Exact, "Exact@Example.com", false),
                entry(2, MatchKind::Exact, "any@case.example", true),
                entry(3, MatchKind::Substring, "Internal.Example", true),
                entry(4, MatchKind::Substring, "CaseKept", false),
                entry(5, MatchKind::Regex, r"^noreply-\d+@", false),
                entry(6, MatchKind::Regex, r"^BOUNCE@", true),
            ],
        );
        assert_eq!(found(&list, "Exact@Example.com"), Some(1));
        assert_eq!(found(&list, "exact@example.com"), None);
        assert_eq!(found(&list, "ANY@Case.Example"), Some(2));
        assert_eq!(found(&list, "ANY@Case.Example.org"), None, "exact is whole");
        assert_eq!(found(&list, "alice@mail.internal.example"), Some(3));
        assert_eq!(found(&list, "xCaseKepty"), Some(4));
        assert_eq!(found(&list, "xcasekepty"), None);
        assert_eq!(found(&list, "noreply-42@x"), Some(5));
        assert_eq!(found(&list, "NOREPLY-42@x"), None);
        assert_eq!(found(&list, "bounce@x"), Some(6));
        assert_eq!(found(&list, "nobody@nowhere"), None);
    }

    #[test]
    fn the_first_entry_that_matches_is_the_one_found() {
        let list = List::new(
            "test_list",
            1,
            vec![
                entry(10, MatchKind::Regex, "evil", false),
                entry(11, MatchKind::Substring, "evil", false),
            ],
        );
        assert_eq!(found(&list, "evil.example"), Some(10));
        let list = List::new(
            "test_list",
            1,
            vec![
                entry(11, MatchKind::Substring, "evil", false),
                entry(10, MatchKind::Regex, "evil", false),
            ],
        );
        assert_eq!(found(&list, "evil.example"), Some(11));
    }

    #[test]
    fn an_expired_entry_matches_nothing() {
        let mut expired = entry(1, MatchKind::Substring, "a", false);
        expired.expires_at = Some(now());
        let mut live = entry(2, MatchKind::Substring, "a", false);
        live.expires_at = Some(now() + chrono::Duration::seconds(1));
        let list = List::new("test_list", 1, vec![expired, live]);
        assert_eq!(found(&list, "a"), Some(2));
    }

    #[test]
    fn a_typed_entry_matches_only_its_type() {
        let mut ip = entry(1, MatchKind::Exact, "192.0.2.1", false);
        ip.observable_type = Some("ipv4".to_owned());
        let list = List::new("typed_list", 1, vec![ip]);
        let find = |kind| list.find(kind, "192.0.2.1", now()).expect("compiles");
        assert!(find(Some("ipv4")).is_some());
        assert!(find(Some("fqdn")).is_none());
        assert!(find(None).is_none());
    }

    #[test]
    fn a_bad_entry_is_refused() {
        let bad = |entry: Entry, spec: &ListSpec| entry.check(spec).expect_err("refused");
        assert_eq!(
            bad(entry(1, MatchKind::Exact, "", false), &SPEC),
            InvalidEntry::Empty
        );
        assert_eq!(
            bad(entry(1, MatchKind::Exact, "a\0b", false), &SPEC),
            InvalidEntry::Nul
        );
        assert!(matches!(
            bad(entry(1, MatchKind::Regex, "(unclosed", false), &SPEC),
            InvalidEntry::Pattern(_)
        ));
        // the regex crate has no lookaround or backreferences, the features that make a
        // backtracking engine slow
        assert!(matches!(
            bad(entry(1, MatchKind::Regex, r"(a)\1", false), &SPEC),
            InvalidEntry::Pattern(_)
        ));
        assert!(matches!(
            bad(entry(1, MatchKind::Regex, r"(?=a)", false), &SPEC),
            InvalidEntry::Pattern(_)
        ));
        assert_eq!(
            bad(entry(1, MatchKind::Regex, r"\w{1000}", false), &SPEC),
            InvalidEntry::PatternTooLarge
        );
        assert_eq!(
            bad(
                entry(
                    1,
                    MatchKind::Regex,
                    &"a".repeat(MAX_PATTERN_BYTES + 1),
                    false
                ),
                &SPEC
            ),
            InvalidEntry::TooLong {
                kind: "regex",
                limit: MAX_PATTERN_BYTES
            }
        );
        assert_eq!(
            bad(
                entry(1, MatchKind::Exact, &"a".repeat(MAX_VALUE_BYTES + 1), false),
                &SPEC
            ),
            InvalidEntry::TooLong {
                kind: "exact",
                limit: MAX_VALUE_BYTES
            }
        );
        assert_eq!(
            bad(entry(1, MatchKind::Exact, "x", false), &TYPED),
            InvalidEntry::NeedsType("typed_list".to_owned())
        );
        let mut typed = entry(1, MatchKind::Exact, "x", false);
        typed.observable_type = Some("ipv4".to_owned());
        assert_eq!(
            bad(typed, &SPEC),
            InvalidEntry::TakesNoType("test_list".to_owned())
        );
        // a pattern that only compiles once wrapped is refused alone, so the wrapping can't
        // change what a stored one means
        assert!(matches!(
            bad(entry(1, MatchKind::Regex, "a)|(b", false), &SPEC),
            InvalidEntry::Pattern(_)
        ));
    }

    #[test]
    fn a_list_of_patterns_too_large_together_is_refused() {
        // each compiles alone; together they pass the list's limit
        let one = r"\w{10}";
        entry(1, MatchKind::Regex, one, true)
            .check(&SPEC)
            .expect("one compiles alone");
        let entries: Vec<Entry> = (0..20)
            .map(|id| entry(id, MatchKind::Regex, one, true))
            .collect();
        assert_eq!(
            List::check(&SPEC, &entries),
            Err(InvalidEntry::ListPatternsTooLarge)
        );
    }

    #[test]
    fn a_long_hostile_input_matches_in_linear_time() {
        // the classic catastrophic pattern for a backtracking engine
        let list = List::new(
            "test_list",
            1,
            vec![entry(1, MatchKind::Regex, r"^(a+)+$", false)],
        );
        let value = format!("{}!", "a".repeat(100_000));
        let started = std::time::Instant::now();
        assert_eq!(found(&list, &value), None);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn names_are_lowercase_words() {
        assert!(ListSpec::valid_name("email_from_whitelist"));
        assert!(!ListSpec::valid_name("Email"));
        assert!(!ListSpec::valid_name(""));
        assert!(!ListSpec::valid_name("a-b"));
        assert!(!ListSpec::valid_name(&"a".repeat(65)));
    }
}
