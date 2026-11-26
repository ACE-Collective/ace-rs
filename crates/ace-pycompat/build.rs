//! Builds `tld`'s two tries from `src/tld/effective_tld_names.dat.txt` as static data, so a parser
//! task, a process of its own, doesn't parse 16,000 lines before its first lookup. The reading
//! follows tld 0.13.2's `BaseMozillaTLDSourceParser.get_tld_names`, quirks included (`src/tld.rs`
//! says which); `tld::tests::the_static_tries_are_the_ones_tld_builds` checks the result against
//! the list read at run time with `pystr`'s functions.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

const DATA: &str = "src/tld/effective_tld_names.dat.txt";

#[derive(Default)]
struct Node {
    // BTreeMap, so each node's labels come out sorted for a binary search
    children: BTreeMap<String, usize>,
    exception: Option<String>,
    leaf: bool,
    private: bool,
}

/// Python's `str.isspace`, which `str.split()` and `str.strip()` go by.
fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\x1c'..='\x20'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Python's `str.splitlines(keepends=True)`.
fn splitlines_keepends(s: &str) -> Vec<&str> {
    let boundary = |c: char| {
        matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    };
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if !boundary(c) {
            continue;
        }
        let mut end = i + c.len_utf8();
        if c == '\r' && s.as_bytes().get(end) == Some(&b'\n') {
            chars.next();
            end += 1;
        }
        out.push(&s[start..end]);
        start = end;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

fn add(nodes: &mut Vec<Node>, tld: &str, private: bool) {
    let mut node = 0;
    for part in tld.split('.').rev() {
        if let Some(exception) = part.strip_prefix('!') {
            nodes[node].exception = Some(exception.to_owned());
            break;
        }
        node = match nodes[node].children.get(part) {
            Some(&child) => child,
            None => {
                nodes.push(Node::default());
                let child = nodes.len() - 1;
                nodes[node].children.insert(part.to_owned(), child);
                child
            }
        };
    }
    nodes[node].leaf = true;
    if private {
        nodes[node].private = true;
    }
}

fn load(data: &str, include_private: bool) -> Vec<Node> {
    let mut nodes = vec![Node::default()];
    let mut private_section = false;
    for line in splitlines_keepends(data) {
        if line.contains("===BEGIN PRIVATE DOMAINS===") {
            private_section = true;
        }
        if private_section && !include_private {
            break;
        }
        let mut line = line;
        if line.contains("// xn--") {
            line = line
                .split(is_space)
                .filter(|w| !w.is_empty())
                .nth(1)
                .unwrap_or("");
        }
        if line.starts_with(['/', '\n']) {
            continue;
        }
        add(&mut nodes, line.trim_matches(is_space), private_section);
    }
    nodes
}

/// A `Trie` literal: every node, then every node's edges, each node's together in label order.
fn emit(out: &mut String, name: &str, nodes: &[Node]) {
    let mut edges = String::new();
    let mut first = 0;
    writeln!(out, "static {name}: Trie = Trie {{\n    nodes: &[").unwrap();
    for node in nodes {
        let exception = match &node.exception {
            Some(e) => format!("Some({e:?})"),
            None => "None".to_owned(),
        };
        writeln!(
            out,
            "        Node {{ first: {first}, count: {}, exception: {exception}, leaf: {}, private: {} }},",
            node.children.len(),
            node.leaf,
            node.private,
        )
        .unwrap();
        for (label, child) in &node.children {
            writeln!(edges, "        ({label:?}, {child}),").unwrap();
        }
        first += node.children.len();
    }
    writeln!(out, "    ],\n    edges: &[\n{edges}    ],\n}};").unwrap();
}

fn main() {
    println!("cargo::rerun-if-changed={DATA}");
    let data = std::fs::read_to_string(DATA).expect("the public suffix list is readable");
    let mut out = String::new();
    emit(&mut out, "FULL", &load(&data, true));
    emit(&mut out, "PUBLIC_ONLY", &load(&data, false));
    let path = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    std::fs::write(path.join("tld_tries.rs"), out).expect("OUT_DIR is writable");
}
