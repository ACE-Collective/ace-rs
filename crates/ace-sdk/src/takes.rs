//! What a module takes: the checks a module makes before it does anything, declared as data over
//! facts the core already holds (PLAN.md decision 23).
//!
//! Most tasks used to end with nothing stored: a module was started on an observable only to
//! find that the file wasn't named `.dmg`, that `file_type` didn't call it an email, or that no
//! module it reads the outputs of had added it (`docs/measurements/task-start.md`). A module now
//! states those checks in `Module::takes`, built from its settings. The statement is data, not
//! code, so the core can evaluate it without running a module's code on what an attacker chose:
//!
//! - the core evaluates it with `Takes::check` before it queues a task, and doesn't queue one the
//!   module would decline (`ace_core::eligibility`), and evaluates it again whenever one of the
//!   facts it reads changes, as eligibility already reruns;
//! - the pool evaluates it again on the leased task, before `analyze`
//!   (`crate::module::run_parser`, `crate::module::run_lookup`), so a task queued before a fact
//!   changed, or queued under the core's audit setting, declines the same way. The module's body
//!   doesn't repeat the checks: there is one statement of what it takes.
//!
//! A module that declares nothing takes everything its inputs, modes and directives allow, as
//! before.
//!
//! **The facts.** Only what the core holds when it decides, and what a leased task carries: the
//! observable's own type, its directives and relationships and whether it redirects; which
//! modules' results added it (a declaration that reads it needs `Module::READS_ADDED_BY`); the
//! root's analysis mode (needs `Module::READS_TREE`); a file's analysis path (its name, its
//! extension, the whole path), its size, the mime type the store recorded for its bytes and its
//! `yara_meta` tags; and the details of the observable's results from the modules it depends on
//! (needs the module in `Module::DEPENDS_ON`). `Manifest::declaration` refuses one that names a
//! fact its module's lease wouldn't carry, so the pool can always check what the core checked.
//! Nothing here reads a file's bytes: a check on those stays in `analyze`.
//!
//! **Exactness.** A rule says what the module's own check said, never a looser or tighter guess:
//! the same subject, the same comparison, the same case rule. Each `Case` names the function a
//! module used. A rule that is false where the module would have gone on loses a detection; the
//! core's audit setting (`ACE4_TAKES_AUDIT`, `ace_core::takes`) is how that is looked for.
//!
//! **Writing one.** Move the checks from the top of `analyze` into `Module::takes`, in the order
//! `analyze` made them, each as a rule with the reason `analyze` gave, and delete them from
//! `analyze`. Only a check that ends the task with `Outcome::Skipped` whatever comes after it can
//! move: one that reads the bytes, delays, fails or writes something stays. Part of a check can
//! move when the part declines on its own, as the email module's "file_type calls it an email or it
//! has `original_email`". A rule that reads which modules added the observable needs
//! `READS_ADDED_BY`, the mode `READS_TREE`, a dependency's result the dependency in `DEPENDS_ON`; a
//! lookup's rules can read a file's path but not its size, mime type or `yara_meta`, which only a
//! parser's lease carries. A pool refuses to start with a declaration that breaks these, and
//! `ace_app::App::modules_with_unusable_declarations` lists them for a binary's test.
//!
//! ```text
//! fn takes(settings: &MySettings) -> Takes {
//!     Takes::everything()
//!         .and(Condition::not_empty(), "an empty file")
//!         .and(Condition::Name(Text::ends_with(".dmg", Case::Lower)), "not named .dmg")
//!         .and(Condition::at_most(settings.maximum_size), "too large")
//! }
//! ```
//!
//! **Checking one.** Run the stack with `ACE4_TAKES_AUDIT=1` in the core's environment over
//! traffic the module sees, `tests/e2e/run` with its comparison among it. The core then queues every
//! task as if nothing were declared and marks the ones a declaration declines; the pool still checks
//! the declaration, so a marked task ends skipped. Any marked task that stored a result or failed is
//! logged at ERROR under `ace_takes` as it ends and listed by `ace_core::takes::audit_report`;
//! `tests/e2e/run` fails on one. An empty report over enough traffic is what lets the setting go.

use std::collections::BTreeMap;
use std::fmt;

use ace_pycompat::fnmatch::fnmatch;
use ace_pycompat::pystr;
use ace_results::{ObservableKind, Relationship, RelationshipKind, YaraMeta};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a module takes: rules that must all hold, each with the reason it gives when it doesn't.
/// No rules takes everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Takes {
    pub rules: Vec<Rule>,
}

/// One check: the module goes on only `when` this holds, and otherwise declines with `otherwise`,
/// the reason its body gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub when: Condition,
    pub otherwise: String,
}

/// A condition over the facts. A condition on a file's facts is false for an observable that
/// isn't a file, and one on a dependency's result is false when there is no such result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// Every one holds; true when empty.
    All(Vec<Condition>),
    /// At least one holds; false when empty.
    Any(Vec<Condition>),
    Not(Box<Condition>),
    /// The observable's own type is one of these. A type that extends one isn't, as when a module
    /// compares the type's name.
    Kind(Vec<ObservableKind>),
    /// The observable has this directive.
    Directive(String),
    /// The observable has a relationship of this kind.
    Relationship(RelationshipKind),
    /// The observable redirects to another (`redirection`).
    Redirected,
    /// A result of this module added the observable (`Module::READS_ADDED_BY`).
    AddedBy(String),
    /// The root's analysis mode is this one (`Module::READS_TREE`).
    Mode(String),
    /// The file's name: the last part of its analysis path.
    Name(Text),
    /// The file's analysis path, as the module sees it.
    Path(Text),
    /// The file's extension as Python's `os.path.splitext` gives it for the name: from its last
    /// dot that isn't a leading one, with the dot; empty when there is none.
    Extension(Text),
    /// The mime type the store recorded for the file's bytes (`InputFile::mime_type`).
    Mime(Text),
    /// The file has this `yara_meta` tag.
    YaraMeta {
        name: String,
        value: String,
    },
    /// The file's size in bytes is in this range, both ends included.
    Size {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<u64>,
    },
    /// The observable has a result from `module`, one the module depends on.
    HasResult(String),
    /// A top-level field of that result's details passes `test`. False without the result or the
    /// field.
    Result {
        module: String,
        field: String,
        test: Field,
    },
}

/// What a field of a dependency's result must be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Field {
    /// The boolean `true`.
    True,
    /// A string that passes the test.
    Text(Text),
}

/// A test on a string, after the case rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    pub test: Match,
    #[serde(default)]
    pub case: Case,
}

/// How a string is compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Match {
    Equals(String),
    EndsWith(String),
    Contains(String),
    /// Equal to one of these.
    OneOf(Vec<String>),
    /// Python's `fnmatch.fnmatch` on POSIX, case-sensitive, of `prefix` and the string together.
    Glob {
        pattern: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
    },
    /// Not empty.
    NotEmpty,
}

/// The case rule a module's comparison used. The pattern is compared as written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    /// Byte for byte.
    #[default]
    Exact,
    /// ASCII letters in either case, as `str::eq_ignore_ascii_case`.
    Ascii,
    /// The string lowered as Python's `str.lower` lowers it (`ace_pycompat::pystr::lower`). Rust's
    /// `str::to_lowercase` lowers to the same ASCII characters: the only characters either lowers
    /// to ASCII are ASCII letters, `U+212A` (Kelvin) and `U+0130` (to `i` and a combining dot), the
    /// same in both, so with a pattern in ASCII the two compare alike.
    Lower,
}

/// The facts a declaration is checked against, as the core holds them when it queues a task and as
/// a leased task carries them.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub kind: ObservableKind,
    pub directives: &'a [String],
    pub relationships: &'a [Relationship],
    pub redirected: bool,
    /// The modules whose results added the observable; read only by `Condition::AddedBy`.
    pub added_by: &'a [String],
    pub mode: Option<&'a str>,
    pub file: Option<FileFacts<'a>>,
    /// The details of the observable's results from the modules the module depends on, by module.
    pub results: &'a BTreeMap<String, Value>,
}

/// A file observable's facts.
#[derive(Debug, Clone, Copy)]
pub struct FileFacts<'a> {
    /// The path it is analyzed under (PLAN.md decision 15).
    pub path: &'a str,
    /// Its size, the store's mime type for its bytes and its `yara_meta` tags: what a parser's
    /// lease carries with the bytes. A lookup's lease carries the path alone, so these are None for
    /// a lookup, and `Manifest::declaration` refuses a lookup's rule that reads them.
    pub size: Option<u64>,
    pub mime: Option<&'a str>,
    pub yara_meta: Option<&'a [YaraMeta]>,
}

/// What a declaration reads that a lease carries only for some modules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reads {
    pub added_by: bool,
    pub mode: bool,
    /// A file's size, mime type or `yara_meta`, which only a parser's lease carries.
    pub file_record: bool,
    /// The modules whose results it reads.
    pub results: Vec<String>,
}

impl Takes {
    /// Takes everything the core's other rules allow: a module that declares nothing.
    pub fn everything() -> Takes {
        Takes::default()
    }

    /// These rules and one more, checked after them.
    pub fn and(mut self, when: Condition, otherwise: impl Into<String>) -> Takes {
        self.rules.push(Rule {
            when,
            otherwise: otherwise.into(),
        });
        self
    }

    /// True when it declares nothing.
    pub fn is_everything(&self) -> bool {
        self.rules.is_empty()
    }

    /// Ok when the module takes an observable with these facts, else the reason of the first rule
    /// that doesn't hold.
    pub fn check(&self, facts: &Facts<'_>) -> Result<(), &str> {
        match self.rules.iter().find(|rule| !rule.when.holds(facts)) {
            Some(rule) => Err(&rule.otherwise),
            None => Ok(()),
        }
    }

    /// What it reads that a lease carries only on request.
    pub fn reads(&self) -> Reads {
        let mut reads = Reads::default();
        for rule in &self.rules {
            rule.when.collect_reads(&mut reads);
        }
        reads.results.sort();
        reads.results.dedup();
        reads
    }

    /// The declaration as JSON, for a module's description.
    pub fn describe(&self) -> Value {
        serde_json::to_value(&self.rules).unwrap_or(Value::Null)
    }
}

impl Condition {
    /// Holds when this doesn't.
    pub fn negated(self) -> Condition {
        Condition::Not(Box::new(self))
    }

    pub fn directive(name: &str) -> Condition {
        Condition::Directive(name.to_owned())
    }

    pub fn added_by(module: &str) -> Condition {
        Condition::AddedBy(module.to_owned())
    }

    pub fn yara_meta(name: &str, value: &str) -> Condition {
        Condition::YaraMeta {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    /// The file isn't empty.
    pub fn not_empty() -> Condition {
        Condition::Size {
            min: Some(1),
            max: None,
        }
    }

    /// The file is at most `max` bytes.
    pub fn at_most(max: u64) -> Condition {
        Condition::Size {
            min: None,
            max: Some(max),
        }
    }

    /// The dependency's boolean field is true.
    pub fn result_true(module: &str, field: &str) -> Condition {
        Condition::Result {
            module: module.to_owned(),
            field: field.to_owned(),
            test: Field::True,
        }
    }

    /// The dependency's string field passes `text`.
    pub fn result_text(module: &str, field: &str, text: Text) -> Condition {
        Condition::Result {
            module: module.to_owned(),
            field: field.to_owned(),
            test: Field::Text(text),
        }
    }

    /// Whether it holds for these facts.
    pub fn holds(&self, facts: &Facts<'_>) -> bool {
        match self {
            Condition::All(all) => all.iter().all(|c| c.holds(facts)),
            Condition::Any(any) => any.iter().any(|c| c.holds(facts)),
            Condition::Not(inner) => !inner.holds(facts),
            Condition::Kind(kinds) => kinds.contains(&facts.kind),
            Condition::Directive(name) => facts.directives.iter().any(|d| d == name),
            Condition::Relationship(kind) => facts.relationships.iter().any(|r| r.kind == *kind),
            Condition::Redirected => facts.redirected,
            Condition::AddedBy(module) => facts.added_by.iter().any(|m| m == module),
            Condition::Mode(mode) => facts.mode == Some(mode.as_str()),
            Condition::Name(text) => facts.file.is_some_and(|f| text.matches(name(f.path))),
            Condition::Path(text) => facts.file.is_some_and(|f| text.matches(f.path)),
            Condition::Extension(text) => facts
                .file
                .is_some_and(|f| text.matches(splitext(name(f.path)).1)),
            Condition::Mime(text) => facts
                .file
                .is_some_and(|f| f.mime.is_some_and(|m| text.matches(m))),
            Condition::YaraMeta { name, value } => facts.file.is_some_and(|f| {
                f.yara_meta
                    .unwrap_or_default()
                    .iter()
                    .any(|m| m.name() == name && m.value() == value)
            }),
            Condition::Size { min, max } => facts.file.and_then(|f| f.size).is_some_and(|size| {
                min.is_none_or(|min| size >= min) && max.is_none_or(|max| size <= max)
            }),
            Condition::HasResult(module) => facts.results.contains_key(module),
            Condition::Result {
                module,
                field,
                test,
            } => facts
                .results
                .get(module)
                .and_then(|details| details.get(field))
                .is_some_and(|value| match (test, value) {
                    (Field::True, Value::Bool(b)) => *b,
                    (Field::Text(text), Value::String(s)) => text.matches(s),
                    _ => false,
                }),
        }
    }

    fn collect_reads(&self, reads: &mut Reads) {
        match self {
            Condition::All(all) | Condition::Any(all) => {
                all.iter().for_each(|c| c.collect_reads(reads));
            }
            Condition::Not(inner) => inner.collect_reads(reads),
            Condition::AddedBy(_) => reads.added_by = true,
            Condition::Mode(_) => reads.mode = true,
            Condition::Mime(_) | Condition::YaraMeta { .. } | Condition::Size { .. } => {
                reads.file_record = true;
            }
            Condition::HasResult(module) | Condition::Result { module, .. } => {
                reads.results.push(module.clone());
            }
            _ => {}
        }
    }
}

impl Text {
    pub fn new(test: Match, case: Case) -> Text {
        Text { test, case }
    }

    pub fn exact(test: Match) -> Text {
        Text::new(test, Case::Exact)
    }

    pub fn ends_with(suffix: &str, case: Case) -> Text {
        Text::new(Match::EndsWith(suffix.to_owned()), case)
    }

    pub fn equals(value: &str) -> Text {
        Text::exact(Match::Equals(value.to_owned()))
    }

    pub fn contains(value: &str) -> Text {
        Text::exact(Match::Contains(value.to_owned()))
    }

    /// Whether `subject` passes.
    pub fn matches(&self, subject: &str) -> bool {
        match self.case {
            Case::Exact => self.test.matches(subject, |a, b| a == b),
            Case::Ascii => self.test.matches(subject, |a, b| a.eq_ignore_ascii_case(b)),
            Case::Lower => self.test.matches(&pystr::lower(subject), |a, b| a == b),
        }
    }
}

impl Match {
    fn matches(&self, subject: &str, same: impl Fn(&str, &str) -> bool) -> bool {
        let suffix = |suffix: &str| {
            subject.len() >= suffix.len()
                && subject.is_char_boundary(subject.len() - suffix.len())
                && same(&subject[subject.len() - suffix.len()..], suffix)
        };
        match self {
            Match::Equals(value) => same(subject, value),
            Match::EndsWith(value) => suffix(value),
            Match::Contains(value) => {
                if value.is_empty() {
                    return true;
                }
                subject.char_indices().any(|(at, _)| {
                    subject.len() - at >= value.len()
                        && subject.is_char_boundary(at + value.len())
                        && same(&subject[at..at + value.len()], value)
                })
            }
            Match::OneOf(values) => values.iter().any(|v| same(subject, v)),
            Match::Glob { pattern, prefix } => fnmatch(&format!("{prefix}{subject}"), pattern),
            Match::NotEmpty => !subject.is_empty(),
        }
    }
}

impl fmt::Display for Takes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.describe())
    }
}

/// The last part of a path.
fn name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `os.path.splitext(name)`: the name and its last extension, with its dot; a leading dot isn't
/// one.
pub fn splitext(name: &str) -> (&str, &str) {
    let start = name.len() - name.trim_start_matches('.').len();
    match name[start..].rfind('.') {
        Some(dot) => name.split_at(start + dot),
        None => (name, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file_facts<'a>(
        path: &'a str,
        size: u64,
        results: &'a BTreeMap<String, Value>,
        yara_meta: &'a [YaraMeta],
    ) -> Facts<'a> {
        Facts {
            kind: ObservableKind::File,
            directives: &[],
            relationships: &[],
            redirected: false,
            added_by: &[],
            mode: None,
            file: Some(FileFacts {
                path,
                size: Some(size),
                mime: Some("text/plain"),
                yara_meta: Some(yara_meta),
            }),
            results,
        }
    }

    #[test]
    fn the_first_rule_that_fails_gives_the_reason() {
        let takes = Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            .and(
                Condition::Name(Text::ends_with(".dmg", Case::Lower)),
                "not named .dmg",
            );
        let none = BTreeMap::new();
        assert_eq!(takes.check(&file_facts("a/b.DMG", 1, &none, &[])), Ok(()));
        assert_eq!(
            takes.check(&file_facts("a/b.dmg", 0, &none, &[])),
            Err("an empty file")
        );
        assert_eq!(
            takes.check(&file_facts("a.dmg/b", 3, &none, &[])),
            Err("not named .dmg")
        );
        assert!(
            Takes::everything()
                .check(&file_facts("x", 0, &none, &[]))
                .is_ok()
        );
    }

    #[test]
    fn each_case_rule_lowers_as_its_function_does() {
        let lower = Text::ends_with(".dmg", Case::Lower);
        let ascii = Text::ends_with(".dmg", Case::Ascii);
        let exact = Text::ends_with(".dmg", Case::Exact);
        for subject in ["x.dmg", "x.DMG", "x.Dmg"] {
            assert!(
                lower.matches(subject) && ascii.matches(subject),
                "{subject}"
            );
        }
        assert!(exact.matches("x.dmg") && !exact.matches("x.DMG"));
        // the Kelvin sign lowers to an ASCII k in Python and in Rust, and isn't one in ASCII
        let k = Text::ends_with(".k", Case::Lower);
        assert!(k.matches("x.\u{212a}"));
        assert_eq!("x.\u{212a}".to_lowercase(), pystr::lower("x.\u{212a}"));
        assert!(!Text::ends_with(".k", Case::Ascii).matches("x.\u{212a}"));
        // a suffix that starts inside a character never matches
        assert!(!Text::ends_with("\u{80}", Case::Exact).matches("\u{100}"));
        assert!(Text::contains("rfc822").matches("message/rfc822"));
        assert!(!Text::contains("rfc822").matches("message/rfc82"));
        assert!(
            Text::exact(Match::Glob {
                pattern: "*.pcap".to_owned(),
                prefix: "/opt/ace/data/root/".to_owned()
            })
            .matches("a/b.pcap")
        );
    }

    #[test]
    fn a_file_condition_is_false_for_an_observable_that_isnt_a_file() {
        let none = BTreeMap::new();
        let facts = Facts {
            kind: ObservableKind::Fqdn,
            directives: &[],
            relationships: &[],
            redirected: false,
            added_by: &[],
            mode: None,
            file: None,
            results: &none,
        };
        for condition in [
            Condition::not_empty(),
            Condition::Name(Text::exact(Match::NotEmpty)),
            Condition::Path(Text::exact(Match::NotEmpty)),
            Condition::Extension(Text::exact(Match::Equals(String::new()))),
            Condition::Mime(Text::exact(Match::NotEmpty)),
            Condition::yara_meta("type", "x"),
        ] {
            assert!(!condition.holds(&facts), "{condition:?}");
            assert!(condition.clone().negated().holds(&facts), "{condition:?}");
        }
    }

    #[test]
    fn a_result_condition_reads_a_field_of_the_dependency() {
        let results = BTreeMap::from([(
            "file_type".to_owned(),
            json!({"mime": "message/rfc822", "is_x509": true, "is_zip_file": false}),
        )]);
        let facts = file_facts("a", 1, &results, &[]);
        assert!(Condition::result_true("file_type", "is_x509").holds(&facts));
        assert!(!Condition::result_true("file_type", "is_zip_file").holds(&facts));
        assert!(!Condition::result_true("file_type", "missing").holds(&facts));
        assert!(!Condition::result_true("other", "is_x509").holds(&facts));
        assert!(
            Condition::result_text("file_type", "mime", Text::equals("message/rfc822"))
                .holds(&facts)
        );
        // a string field isn't true, and a boolean doesn't match text
        assert!(!Condition::result_true("file_type", "mime").holds(&facts));
        assert!(
            !Condition::result_text("file_type", "is_x509", Text::exact(Match::NotEmpty))
                .holds(&facts)
        );
        assert!(Condition::HasResult("file_type".to_owned()).holds(&facts));
    }

    #[test]
    fn the_extension_is_python_s() {
        assert_eq!(splitext("a.tar.gz"), ("a.tar", ".gz"));
        assert_eq!(splitext(".bashrc"), (".bashrc", ""));
        assert_eq!(splitext("..x.doc"), ("..x", ".doc"));
        assert_eq!(splitext("noext"), ("noext", ""));
        let none = BTreeMap::new();
        let doc = Condition::Extension(Text::exact(Match::OneOf(vec![".doc".to_owned()])));
        assert!(doc.holds(&file_facts("dir.x/a.doc", 1, &none, &[])));
        assert!(!doc.holds(&file_facts("a.doc/b", 1, &none, &[])));
    }

    #[test]
    fn a_declaration_says_what_it_reads_and_round_trips() {
        let takes = Takes::everything()
            .and(Condition::added_by("officeparser3"), "not an output")
            .and(
                Condition::Any(vec![
                    Condition::Mode("correlation".to_owned()),
                    Condition::result_true("file_type", "is_x509"),
                ]),
                "x",
            );
        assert_eq!(
            takes.reads(),
            Reads {
                added_by: true,
                mode: true,
                file_record: false,
                results: vec!["file_type".to_owned()],
            }
        );
        let back: Takes =
            serde_json::from_value(json!({"rules": takes.describe()})).expect("reads");
        assert_eq!(back, takes);
        let meta = ["type=email.attachment".parse::<YaraMeta>().expect("valid")];
        assert!(
            Condition::yara_meta("type", "email.attachment").holds(&file_facts(
                "a",
                1,
                &BTreeMap::new(),
                &meta
            ))
        );
    }
}
