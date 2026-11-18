//! `is_javascript_file` of ace3's `is_file_type.py`: `node --check` passes on the file, and grep
//! finds a JavaScript keyword, an arrow, a `.then(` or a call in it.
//!
//! ace3 runs node 24 on the file, hard-linked to a name ending in `.js` when it has none. ace4
//! parses with oxc (PLAN.md 7.3), as node checks a `.js` file: as a CommonJS module, wrapped in a
//! function, and when that fails as an ES module, which node 24 tries when CommonJS fails on module
//! syntax. oxc's semantic pass adds the early errors V8 raises, such as a redeclared `let`, and
//! the proposals oxc parses and V8 13.6 doesn't ship fail, as they do in node.
//! `docs/measurements/javascript-check.md` lists where the two disagree.
//!
//! - A name already ending in `.js` in another case, such as `invoice.JS`, isn't linked, and node
//!   refuses the extension, so the check fails, as it does in ace3.
//! - node reads the file as UTF-8, with U+FFFD for what isn't, and drops a byte order mark.
//! - V8 gives up on nesting between about 1,560 and 2,840 levels, by construct, so a file whose
//!   brackets nest deeper than [`MAX_NESTING`] fails here, as it does in node.
//! - oxc has no limit of its own on recursion, and a contained task can't catch a stack overflow.
//!   So oxc parses on a stack of its own, sized for the worst the file could nest
//!   ([`parse_stack`]), and a file that could need more than [`MAX_STACK`] fails the check.

use std::sync::LazyLock;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AccessorProperty, Decorator, ImportDeclaration, ImportExpression, ImportPhase, WithClause,
    WithClauseKeyword,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use regex::bytes::Regex;

/// Brackets deeper than this fail the check without parsing. V8's own limit under node's
/// default stack is 1,560 for nested object literals, the lowest of the constructs measured.
pub const MAX_NESTING: usize = 1_560;

/// grep's pattern, `grep -Eq` in ace3's C.UTF-8 locale, matched line by line.
static KEYWORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(function|var|let|const|class|async|await|return|if|for|while|try|catch|import|export)\b|=>|\.\s*then\(|\w\(",
    )
    .expect("the pattern compiles")
});

/// `is_javascript_file(path)` on a file whose alert path is `path` and whose bytes are `data`.
pub fn is_javascript_file(path: &str, data: &[u8]) -> bool {
    !ace_results::types::file_type::javascript_name_refused(path) && javascript_bytes(data)
}

/// Whether `node --check` exits 0, as ace3 runs it.
pub fn node_checks(path: &str, data: &[u8]) -> bool {
    // a name that ends in .js in another case keeps its name, which node refuses
    !ace_results::types::file_type::javascript_name_refused(path) && node_parses(data)
}

/// The part of `is_javascript_file` that reads the bytes alone: node would parse them under a
/// name it takes, and a line has a keyword. The type step keeps it as a fact of the bytes
/// (`TypeFacts::javascript`).
pub fn javascript_bytes(data: &[u8]) -> bool {
    node_parses(data)
        && data
            .split(|b| *b == b'\n')
            .any(|line| KEYWORDS.is_match(line))
}

/// `node --check` on the bytes under a name node takes.
fn node_parses(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    if max_nesting(text.as_bytes()) > MAX_NESTING {
        return false;
    }
    let Some(stack) = parse_stack(text.as_bytes()) else {
        return false;
    };
    stacker::grow(stack, || {
        parses(text, SourceType::cjs()) || parses(text, SourceType::mjs())
    })
}

/// The most stack oxc may be given, which the task's address space has to hold.
pub const MAX_STACK: usize = 1 << 30;

/// Stack for oxc's parse and semantic pass of the text, or None when that could pass
/// [`MAX_STACK`]. Each level of oxc's recursion starts at a token: a bracket, an operator or a
/// keyword that opens a nested statement or expression. Every byte that could be one, in a string
/// or not, and every keyword-like word counts, so the count is at least the parse's depth. The
/// costliest level measured is a little over 1 KiB (`x=>`, docs/measurements/javascript-check.md),
/// so each counts 1.5 KiB, over the 16 MiB the rest of the work may use.
pub fn parse_stack(text: &[u8]) -> Option<usize> {
    const NESTING_WORDS: &[&[u8]] = &[
        b"if",
        b"else",
        b"while",
        b"for",
        b"do",
        b"with",
        b"new",
        b"typeof",
        b"void",
        b"delete",
        b"await",
        b"yield",
        b"return",
        b"throw",
        b"case",
        b"function",
        b"class",
        b"async",
        b"in",
        b"of",
        b"instanceof",
        b"extends",
        b"import",
        b"export",
        b"let",
        b"const",
        b"var",
    ];
    let mut count: usize = 0;
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < text.len() && (text[i].is_ascii_alphanumeric() || text[i] == b'_') {
                i += 1;
            }
            if NESTING_WORDS.contains(&&text[start..i]) {
                count += 1;
            }
            continue;
        }
        if matches!(
            c,
            b'(' | b'['
                | b'{'
                | b'$'
                | b'='
                | b'?'
                | b':'
                | b'!'
                | b'~'
                | b'+'
                | b'-'
                | b'@'
                | b'*'
                | b'<'
                | b'>'
                | b'.'
                | b','
                | b'#'
                | b'/'
        ) {
            count += 1;
        }
        i += 1;
    }
    let stack = (16usize << 20).checked_add(count.checked_mul(1536)?)?;
    (stack <= MAX_STACK).then_some(stack)
}

/// oxc parses the text as this kind of file, with V8's early errors, without an error.
fn parses(text: &str, source_type: SourceType) -> bool {
    let allocator = Allocator::default();
    let options = ParseOptions {
        parse_regular_expression: true,
        ..ParseOptions::default()
    };
    let parsed = Parser::new(&allocator, text, source_type)
        .with_options(options)
        .parse();
    if parsed.fatal_error || parsed.diagnostics.has_errors() {
        return false;
    }
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if semantic.diagnostics.has_errors() {
        return false;
    }
    let mut unshipped = Unshipped(false);
    unshipped.visit_program(&parsed.program);
    !unshipped.0
}

/// Proposals oxc parses and node 24's V8 (13.6) doesn't: decorators, `accessor` fields, import
/// attributes written with `assert`, which V8 dropped, and `import defer`. V8 has `import source`.
struct Unshipped(bool);

impl<'a> Visit<'a> for Unshipped {
    fn visit_decorator(&mut self, _: &Decorator<'a>) {
        self.0 = true;
    }

    fn visit_accessor_property(&mut self, _: &AccessorProperty<'a>) {
        self.0 = true;
    }

    fn visit_with_clause(&mut self, it: &WithClause<'a>) {
        if it.keyword == WithClauseKeyword::Assert {
            self.0 = true;
        }
        walk::walk_with_clause(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if it.phase == Some(ImportPhase::Defer) {
            self.0 = true;
        }
        walk::walk_import_declaration(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if it.phase == Some(ImportPhase::Defer) {
            self.0 = true;
        }
        walk::walk_import_expression(self, it);
    }
}

/// The deepest nesting of `(`, `[` and `{` in the text, outside strings, templates' text and
/// comments. Regular expressions aren't told apart from division, so a bracket in one counts: the
/// result can be more than the parse's depth, never less, which is the side a guard needs.
pub fn max_nesting(text: &[u8]) -> usize {
    let mut depth: usize = 0;
    let mut deepest = 0;
    // the depths at which a template's `${` opened, to go back to its text at the `}`
    let mut templates: Vec<usize> = Vec::new();
    let mut i = 0;
    let n = text.len();
    while i < n {
        let c = text[i];
        match c {
            b'(' | b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b')' | b']' => depth = depth.saturating_sub(1),
            b'}' => {
                if templates.last() == Some(&depth) {
                    templates.pop();
                    i = skip_template(text, i + 1, &mut templates, &mut depth, &mut deepest);
                    continue;
                }
                depth = depth.saturating_sub(1);
            }
            b'\'' | b'"' => {
                i += 1;
                while i < n && text[i] != c && text[i] != b'\n' {
                    if text[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'`' => {
                i = skip_template(text, i + 1, &mut templates, &mut depth, &mut deepest);
                continue;
            }
            b'/' if text.get(i + 1) == Some(&b'/') => {
                while i < n && text[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if text.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < n && !(text[i] == b'*' && text[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    deepest
}

/// Skips a template's text from `i`, up to its closing backtick or a `${`, which opens a level.
/// Returns where scanning goes on.
fn skip_template(
    text: &[u8],
    mut i: usize,
    templates: &mut Vec<usize>,
    depth: &mut usize,
    deepest: &mut usize,
) -> usize {
    while i < text.len() {
        match text[i] {
            b'\\' => i += 2,
            b'`' => return i + 1,
            b'$' if text.get(i + 1) == Some(&b'{') => {
                *depth += 1;
                *deepest = (*deepest).max(*depth);
                templates.push(*depth);
                return i + 2;
            }
            _ => i += 1,
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_s_two_tries_and_the_name_rule() {
        assert!(node_checks("a.js", b"return 5;\n"));
        assert!(node_checks("a.js", b"import x from 'y';\n"));
        assert!(node_checks("a.js", b"await 1;\n"));
        assert!(node_checks("a.js", b"new.target\n"));
        assert!(!node_checks("a.js", b"return 5;\nimport x from 'y';\n"));
        assert!(!node_checks("a.js", b"let a; let a;\n"));
        assert!(!node_checks("a.JS", b"var a = 1\n"));
        assert!(node_checks("a.txt", b"var a = 1\n"));
        assert!(node_checks("a.js", b"\xef\xbb\xbfvar a = 1\n"));
    }

    #[test]
    fn grep_s_pattern() {
        assert!(is_javascript_file("a.js", b"var a = 1\n"));
        assert!(is_javascript_file("a.js", b"x.then(1)\n"));
        assert!(!is_javascript_file("a.js", b"x.then (1)\n"));
        assert!(!is_javascript_file("a.js", b"1 + 2\n"));
        assert!(!is_javascript_file("a.js", b"1 +\n then\n"));
    }

    #[test]
    fn nesting_skips_strings_comments_and_template_text() {
        assert_eq!(max_nesting(b"((a))"), 2);
        assert_eq!(max_nesting(b"'(((' // ((((\n/* [[[ */ [1]"), 1);
        assert_eq!(max_nesting(b"`((( ${ (a) } (((`"), 2);
        let deep = format!("var a = {}1{};", "(".repeat(3000), ")".repeat(3000));
        assert!(!node_checks("a.js", deep.as_bytes()));
    }
}

/// The cases `tests/data/js_oracle.py` recorded from node 24 in ace3's container, and where oxc
/// answers otherwise. docs/measurements/javascript-check.md explains each.
#[cfg(test)]
mod oracle {
    use super::*;
    use base64::Engine;
    use serde_json::Value;

    /// The sources where ace4 and node disagree, with node's answer.
    fn disagreements() -> (usize, Vec<(String, bool)>) {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/js_cases.json");
        let cases: Value =
            serde_json::from_slice(&std::fs::read(path).expect("cases")).expect("json");
        let cases = cases["cases"].as_array().expect("cases");
        let mut out = Vec::new();
        for case in cases {
            let source = base64::engine::general_purpose::STANDARD
                .decode(case["source"].as_str().expect("source"))
                .expect("base64");
            let node = case["node_check"].as_bool().expect("node");
            let ours = node_checks("case.js", &source);
            if ours == node {
                assert_eq!(
                    is_javascript_file("case.js", &source),
                    case["is_javascript_file"]
                        .as_bool()
                        .expect("is_javascript_file"),
                    "grep's answer differs for {:?}",
                    String::from_utf8_lossy(&source)
                );
            }
            if ours != node {
                out.push((String::from_utf8_lossy(&source).into_owned(), node));
            }
        }
        (cases.len(), out)
    }

    #[test]
    fn oxc_agrees_with_node_but_for_the_listed_cases() {
        let (count, found) = disagreements();
        for (source, node) in &found {
            eprintln!("node says {node}: {source:?}");
        }
        eprintln!("{} of {count} cases disagree", found.len());
        let listed: Vec<(&str, bool)> = LISTED.to_vec();
        let found: Vec<(&str, bool)> = found.iter().map(|(s, n)| (s.as_str(), *n)).collect();
        assert_eq!(found, listed);
    }

    /// Each case where oxc and V8 disagree, with node's answer.
    const LISTED: &[(&str, bool)] = &[];
}

#[cfg(test)]
mod depth {
    use super::*;

    /// At the guard's depth oxc parses each construct within 3 MiB of stack, under half the 8 MiB
    /// the task's main thread has. A dev build needs more than 2 MiB.
    #[test]
    fn oxc_parses_the_deepest_nesting_the_guard_lets_through() {
        std::thread::Builder::new()
            .stack_size(3 << 20)
            .spawn(parse_deepest)
            .expect("spawns")
            .join()
            .expect("parses");
    }

    fn parse_deepest() {
        let n = MAX_NESTING;
        let cases = [
            format!("var a = {}1{};", "(".repeat(n), ")".repeat(n)),
            format!("var a = {}{};", "[".repeat(n), "]".repeat(n)),
            format!("{}{}", "{".repeat(n), "}".repeat(n)),
            format!("var a = {}1{};", "{a:".repeat(n), "}".repeat(n)),
            format!("{}{}", "function f(){".repeat(n), "}".repeat(n)),
            format!("var a = {}1{};", "`${".repeat(n), "}`".repeat(n)),
        ];
        for case in cases {
            assert_eq!(max_nesting(case.as_bytes()), n);
            node_checks("a.js", case.as_bytes());
        }
    }
}

/// `ACE4_JS_DEPTH=<n> ACE4_JS_KIND=<prefix> cargo test -p ace-mod-files --lib probe_depth -- --ignored`
/// parses the prefix repeated n times on an 8 MiB stack, for docs/measurements/javascript-check.md.
#[cfg(test)]
#[test]
#[ignore]
fn probe_depth() {
    let n: usize = std::env::var("ACE4_JS_DEPTH")
        .expect("depth")
        .parse()
        .expect("number");
    let kind = std::env::var("ACE4_JS_KIND").expect("kind");
    let text = format!("{}1", kind.repeat(n));
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(move || parses(&text, SourceType::cjs()))
        .expect("spawns")
        .join()
        .expect("parses");
}

#[cfg(test)]
mod hostile {
    use super::*;

    /// Chains nested past any stack a thread has parse on the grown stack, on a test thread's
    /// 2 MiB, and give node's answer: V8 runs out of stack on each.
    #[test]
    fn deep_chains_without_brackets_parse_on_their_own_stack() {
        for (kind, n) in [
            ("x=>", 100_000),
            ("!", 400_000),
            ("a=", 100_000),
            ("if(1)", 100_000),
        ] {
            let text = format!("{}1", kind.repeat(n));
            let started = std::time::Instant::now();
            node_checks("a.js", text.as_bytes());
            eprintln!("{kind} x {n}: {:?}", started.elapsed());
        }
        let text = "x=>".repeat(400_000);
        assert_eq!(parse_stack(text.as_bytes()), None);
        assert!(!node_checks("a.js", text.as_bytes()));
    }
}
