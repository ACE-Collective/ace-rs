//! The bounds, each at its limit and one past it, and what a crafted file can't hide from the count.
//! `docs/measurements/yara-guard.md` has the numbers the limits stand on.

use super::*;
use crate::load::new_compiler;

/// A source for each thing yara-x recurses on, holding `n` of it.
fn crafted(construct: &str, n: usize) -> String {
    let rep = |s: &str| s.repeat(n);
    match construct {
        "text_escapes" => format!(
            "rule r {{ strings: $a = \"{}\" condition: $a }}",
            rep("\\\\")
        ),
        "meta_escapes" => format!("rule r {{ meta: m = \"{}\" condition: true }}", rep("\\\"")),
        "regex_escapes" => format!("rule r {{ strings: $a = /a{}/ condition: $a }}", rep("\\.")),
        "condition_escapes" => format!("rule r {{ condition: filename == \"{}\" }}", rep("\\\\")),
        "triple_quoted" => format!(
            "rule r {{ meta: m = \"\"\"{}\"\"\" condition: true }}",
            rep("\\\\\n")
        ),
        "comment_runs" => format!("rule r {{ condition: /*\n{}*/ true }}", rep(" * text\n")),
        "wide_spaces" => format!("rule r {{ condition:{} true }}", rep("\u{a0}")),
        "parens" => format!("rule r {{ condition: {}true{} }}", rep("("), rep(")")),
        "not" => format!("rule r {{ condition: {}true }}", rep("not ")),
        "minus" => format!("rule r {{ condition: {}1 == 1 }}", rep("- ")),
        "bitwise_not" => format!("rule r {{ condition: {}1 == 1 }}", rep("~")),
        "for" => format!(
            "rule r {{ condition: {}true{} }}",
            (0..n)
                .map(|i| format!("for any i{i} in (1..2) : ( "))
                .collect::<String>(),
            rep(" )")
        ),
        "with" => format!(
            "rule r {{ condition: {}true{} }}",
            (0..n)
                .map(|i| format!("with v{i} = 1 : ( "))
                .collect::<String>(),
            rep(" )")
        ),
        "boolean" => format!(
            "rule r {{ condition: {}true{} }}",
            rep("(true and "),
            rep(")")
        ),
        "index" => format!(
            "import \"pe\" rule r {{ condition: {}0{} == 0 }}",
            rep("pe.sections["),
            rep("].raw_data_size")
        ),
        "hex_alternatives" => format!(
            "rule r {{ strings: $a = {{ 01 02 03 04 {}05{} }} condition: $a }}",
            rep("( 06 | "),
            rep(" )")
        ),
        "calls" => format!(
            "import \"math\" rule r {{ condition: {}1{} == 1 }}",
            rep("math.abs("),
            rep(")")
        ),
        "builtin_calls" => format!(
            "rule r {{ condition: {}0{} == 1 }}",
            rep("uint32("),
            rep(")")
        ),
        "open_parens" => format!("rule r {{ condition: {} }}", rep("(")),
        "open_hex" => format!(
            "rule r {{ strings: $a = {{ {} condition: $a }}",
            rep("( 01 | ")
        ),
        other => panic!("no construct {other}"),
    }
}

/// Each construct with its bound, and what refuses one past it.
const BOUNDS: &[(&str, usize, &str)] = &[
    ("text_escapes", MAX_ESCAPES, "escape sequences"),
    ("meta_escapes", MAX_ESCAPES, "escape sequences"),
    ("regex_escapes", MAX_ESCAPES, "escape sequences"),
    ("condition_escapes", MAX_ESCAPES, "escape sequences"),
    ("triple_quoted", MAX_ESCAPES, "triple-quoted"),
    ("comment_runs", MAX_COMMENT_RUNS, "runs of `*`"),
    ("wide_spaces", MAX_WIDE_SPACES, "spaces outside ASCII"),
    ("parens", MAX_NESTING, "nests brackets"),
    ("not", MAX_NESTING, "nests brackets"),
    ("minus", MAX_NESTING, "nests brackets"),
    ("bitwise_not", MAX_NESTING, "nests brackets"),
    ("for", MAX_NESTING, "nests brackets"),
    ("with", MAX_NESTING, "nests brackets"),
    ("boolean", MAX_NESTING, "nests brackets"),
    ("index", MAX_NESTING, "nests brackets"),
    ("hex_alternatives", MAX_NESTING, "nests brackets"),
    ("calls", MAX_CALL_NESTING, "nests calls"),
    ("builtin_calls", MAX_CALL_NESTING, "nests calls"),
    ("open_parens", MAX_NESTING, "nests brackets"),
    ("open_hex", MAX_NESTING, "nests brackets"),
];

/// Compiles `source` as the loader does and parses it as `crate::source` does, on a thread with
/// `stack` bytes. Returns whether it compiled. An overflow aborts the test binary.
fn compiles_on(stack: usize, source: String) -> bool {
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(move || {
            crate::source::rules(source.as_bytes());
            let mut compiler = new_compiler();
            let compiled = compiler.add_source(source.as_bytes()).is_ok();
            drop(compiler.build());
            compiled
        })
        .expect("spawns")
        .join()
        .expect("the compile doesn't panic")
}

#[test]
fn each_bound_passes_at_its_limit_and_refuses_one_past_it() {
    for (construct, bound, reason) in BOUNDS {
        let at = crafted(construct, *bound);
        assert_eq!(check(at.as_bytes()), Ok(()), "{construct} at {bound}");
        let over = crafted(construct, bound + 1);
        let refusal = check(over.as_bytes()).expect_err(construct).to_string();
        assert!(refusal.contains(reason), "{construct}: {refusal}");
        // far past the bound, where yara-x would overflow, the count is as cheap
        let far = crafted(construct, 100_000);
        assert!(check(far.as_bytes()).is_err(), "{construct} at 100,000");
    }
}

/// What the bounds are for: a file at every limit compiles and parses on 1.5 MiB, three quarters of
/// the smallest stack rule source is compiled on. The escapes sit at the deepest level, since the
/// lexer runs on top of the parser's frames.
#[test]
fn a_file_at_every_bound_fits_a_small_stack() {
    const STACK: usize = 3 << 19;
    for (construct, bound, _) in BOUNDS {
        // the two that are syntax errors parse, and are refused by yara-x
        let valid = !construct.starts_with("open_");
        assert_eq!(
            compiles_on(STACK, crafted(construct, *bound)),
            valid,
            "{construct} at {bound}"
        );
    }

    let escapes = "\\\\".repeat(MAX_ESCAPES);
    let comment = " * text\n".repeat(MAX_COMMENT_RUNS);
    let deepest = [
        format!("filename == \"{escapes}\""),
        format!("filename matches /a{}/", "\\.".repeat(MAX_ESCAPES)),
        format!("/*\n{comment}*/ true"),
        format!("{}true", "\u{a0}".repeat(MAX_WIDE_SPACES)),
    ];
    for inner in &deepest {
        let nested = [
            format!(
                "rule r {{ condition: {}{inner}{} }}",
                "(".repeat(MAX_NESTING),
                ")".repeat(MAX_NESTING)
            ),
            format!(
                "rule r {{ condition: {}{inner}{} }}",
                "(true and ".repeat(MAX_NESTING),
                ")".repeat(MAX_NESTING)
            ),
            format!(
                "rule r {{ condition: {}{inner}{} }}",
                (0..MAX_NESTING)
                    .map(|i| format!("for any i{i} in (1..2) : ( "))
                    .collect::<String>(),
                " )".repeat(MAX_NESTING)
            ),
            format!(
                "rule r {{ condition: {}({inner}) }}",
                "not ".repeat(MAX_NESTING - 1)
            ),
        ];
        for source in nested {
            assert_eq!(check(source.as_bytes()), Ok(()));
            assert!(compiles_on(STACK, source));
        }
    }
    // brackets, unary operators and indexes together, at the bound
    let mixed = format!(
        "import \"pe\" rule r {{ condition: {}0{} == 0 }}",
        "pe.sections[(- ".repeat(MAX_NESTING / 3),
        ")].raw_data_size".repeat(MAX_NESTING / 3)
    );
    assert_eq!(check(mixed.as_bytes()), Ok(()));
    assert!(compiles_on(STACK, mixed));
}

/// Brackets in a string, a regex or a comment aren't nesting, so rules that hold them load.
#[test]
fn brackets_inside_literals_and_comments_are_not_nesting() {
    let deep = "(".repeat(200);
    let source = format!(
        "rule r {{\n  meta: m = \"{deep}\" t = \"\"\"{deep}\n{deep}\"\"\"\n  strings:\n    $a = \
         \"{deep}\\\"{deep}\" // {deep}\n    $b = /\\({deep_escaped}[(]x\\//is /* {deep} */\n    $c = \
         {{ 01 ??(02|03)?? [1-2] ~04 }}\n  condition: any of ($a, $b, $c) and #a in (0..10) // \
         {deep}\n}}\n",
        deep_escaped = "\\(".repeat(200)
    );
    assert_eq!(check(source.as_bytes()), Ok(()));
    assert!(compiles_on(2 << 20, source));

    // hex strings whose brackets touch a wildcard balance, however many there are
    let many = format!(
        "rule r {{ strings: {} condition: any of them }}",
        (0..200)
            .map(|i| format!("$a{i} = {{ 01 02 ??(03|04)?? 05 }} "))
            .collect::<String>()
    );
    assert_eq!(check(many.as_bytes()), Ok(()));
    // and so do rules a `}` ends with a bracket left open
    let leaky = "rule r { condition: (( }\n".repeat(200);
    assert_eq!(check(leaky.as_bytes()), Ok(()));
}

/// A crafted file can't hide real nesting from the count: where yara-x's tokenizer makes an unknown
/// token, or a quote or a slash opens nothing, the brackets that follow still count.
#[test]
fn crafted_text_does_not_hide_nesting() {
    let deep = "(".repeat(3000);
    for hostile in [
        // a string that never closes: yara-x reads on after the line
        format!("rule r {{ condition: \"abc\n{deep} }}"),
        // one that looks closed by an escaped quote
        format!("rule r {{ condition: \"abc\\\"\n{deep} }}"),
        // a comment opened inside a string isn't a comment
        format!("rule r {{ condition: \"/*\" and {deep} /* */ }}"),
        // a comment that never closes is one unknown token to the end
        format!("rule r {{ condition: /* {deep} }}"),
        // a regex can't start with `*` or span a line
        format!("rule r {{ condition: /\n{deep}/ }}"),
        format!("rule r {{ condition: 1 / 2\n{deep} /i }}"),
        // a triple-quoted string that never closes is an empty string and a quote
        format!("rule r {{ condition: \"\"\"\n{deep} }}"),
        // closes inside a string don't balance real opens
        format!(
            "rule r {{ condition: {} \"{}\" {} }}",
            "(".repeat(20),
            ")".repeat(20),
            "(".repeat(20)
        ),
        // characters yara-x has no token for
        format!("rule r {{ condition: `{deep} }}"),
        format!("rule r {{ condition: \u{e9}{deep} }}"),
        format!("rule r {{ condition: \u{663}{deep} }}"),
        // a line comment ends at its line
        format!("rule r {{ condition: // \n{deep} }}"),
    ] {
        let refusal = check(hostile.as_bytes());
        assert!(
            matches!(refusal, Err(Refusal::Nesting { .. })),
            "{refusal:?} for {:?}",
            &hostile[..60.min(hostile.len())]
        );
    }
    // the lexer's bounds need no idea of context: in a comment, a string or bare
    let escapes = "\\\\".repeat(3000);
    for hostile in [
        format!("rule r {{ condition: true }} // \"{escapes}"),
        format!("rule r {{ condition: \"{escapes}"),
        format!("rule r {{ condition: /{escapes}"),
        escapes.clone(),
    ] {
        assert_eq!(check(hostile.as_bytes()), Err(Refusal::Escapes { line: 1 }));
    }
    let runs = "* ".repeat(3000);
    for hostile in [
        format!("rule r {{ condition: /* {runs}"),
        format!("rule r {{ condition: \"x\" /**/ /* {runs} */ true }}"),
        format!("/*/ {runs} */"),
    ] {
        assert!(matches!(
            check(hostile.as_bytes()),
            Err(Refusal::CommentRuns { .. })
        ));
    }
}

/// What real rules hold stays well inside the bounds: operators, wildcards and comments in number.
#[test]
fn ordinary_rules_pass() {
    let mut source = String::from("/*\n * A banner.\n ***********/\nimport \"pe\"\n");
    for i in 0..2000 {
        source.push_str(&format!(
            "rule r{i} : tag {{\n  meta: path = \"C:\\\\Windows\\\\System32\\\\x.dll\"\n  strings:\n    \
             $s1 = \"a\\\\b\\x00\" wide\n    $s2 = /https?:\\/\\/[a-z]{{1,20}}\\.example\\/.*/ nocase\n  \
             condition:\n    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x4550 and any of \
             ($s*) and not (filesize > 2MB or -1 == ~0) and 10 \\ 2 * 3 == 15\n}}\n"
        ));
    }
    assert_eq!(check(source.as_bytes()), Ok(()));
}

/// The include statements of a source, as yara-x's tokenizer makes them: the keyword and the string
/// after it, across space and comments, and whether it stands outside every rule. `crate::include`
/// resolves the ones that do, and holds each included file to these bounds (its tests).
#[test]
fn include_statements_are_found_where_yara_x_takes_them() {
    let source = "include \"one.yar\"\n\
                  rule r { strings: $a = { 01 02 } $b = \"include \\\"no.yar\\\"\" condition: true }\n\
                  // include \"commented.yar\"\n/* include \"also.yar\" */\n\
                  include\n/* x */ \"./two.yar\" include\"three.yar\"\n\
                  rule s { condition: true\ninclude \"inside.yar\" }\n\
                  include \"\"\"triple.yar\"\"\"\ninclude four\n\"not.yar\"";
    let sites = includes(source.as_bytes()).expect("within the bounds");
    let found: Vec<(&str, usize, bool)> = sites
        .iter()
        .map(|site| {
            (
                std::str::from_utf8(&site.path).expect("text"),
                site.line,
                site.top_level,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("one.yar", 1, true),
            ("./two.yar", 5, true),
            ("three.yar", 6, true),
            ("inside.yar", 8, false),
        ]
    );
    // the span is the whole statement
    assert_eq!(&source[sites[0].span.clone()], "include \"one.yar\"");
    assert_eq!(
        &source[sites[1].span.clone()],
        "include\n/* x */ \"./two.yar\""
    );
    // a source past a bound has no includes to give: it is refused first
    let deep = format!(
        "include \"x.yar\" rule r {{ condition: {} }}",
        "(".repeat(5000)
    );
    assert!(matches!(
        includes(deep.as_bytes()),
        Err(Refusal::Nesting { .. })
    ));
}
