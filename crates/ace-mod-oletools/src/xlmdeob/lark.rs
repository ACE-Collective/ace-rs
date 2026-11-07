//! lark 0.12's LALR parser and contextual lexer, on tables made from XLMMacroDeobfuscator's grammar by
//! `tools/xlm/make-tables`. Which formulas parse, and into what tree, decides what a macro does.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use fancy_regex::{Regex, RegexBuilder};

use super::grammar_tables::{
    END_STATE, IGNORE, LEXER_OF_STATE, LEXERS, NEWLINE_TERMINALS, ORIGINS, RULES, START_STATE,
    STATES, TERMINALS,
};
use super::value::Value;
use crate::py::repr_str;

/// `Token`: a str whose `value` the interpreter overwrites, so `str(token)` and `token.value` part.
pub struct Token {
    pub kind: u16,
    pub text: String,
    pub value: RefCell<Value>,
    line: usize,
    column: usize,
}

impl Token {
    fn new(kind: u16, text: &str, line: usize, column: usize) -> Rc<Token> {
        Rc::new(Token {
            kind,
            text: text.to_owned(),
            value: RefCell::new(Value::str(text)),
            line,
            column,
        })
    }

    pub fn kind_name(&self) -> &'static str {
        TERMINALS.get(usize::from(self.kind)).map_or("", |t| t.0)
    }

    /// `Token.update(None, value)`.
    pub fn with_value(&self, value: &str) -> Rc<Token> {
        Token::new(self.kind, value, self.line, self.column)
    }

    /// `repr(token)`.
    pub fn repr(&self) -> String {
        format!(
            "Token({}, {})",
            repr_str(self.kind_name()),
            self.value.borrow().repr()
        )
    }
}

/// `Tree`. Its children change when a macro calls a registered function.
pub struct Tree {
    pub data: &'static str,
    pub children: RefCell<Vec<Node>>,
}

// A deep tree must not take the stack with it. Each node is Rc'd, and one still held elsewhere stops here.
impl Drop for Tree {
    fn drop(&mut self) {
        let mut stack = std::mem::take(self.children.get_mut());
        while let Some(node) = stack.pop() {
            if let Node::Tree(tree) = node
                && let Some(tree) = Rc::into_inner(tree)
            {
                let mut tree = tree;
                stack.append(tree.children.get_mut());
            }
        }
    }
}

/// A child of a tree, or what a handler gets as an argument: an empty argument is Python's `[]`.
#[derive(Clone)]
pub enum Node {
    Token(Rc<Token>),
    Tree(Rc<Tree>),
    EmptyList,
}

impl Node {
    /// `repr(node)`, which is also `str(tree)`. Iterative, so it can't take the stack.
    pub fn repr(&self) -> String {
        enum Work {
            Node(Node),
            Text(&'static str),
        }
        let mut out = String::new();
        let mut stack = vec![Work::Node(self.clone())];
        while let Some(work) = stack.pop() {
            match work {
                Work::Text(text) => out.push_str(text),
                Work::Node(Node::EmptyList) => out.push_str("[]"),
                Work::Node(Node::Token(token)) => out.push_str(&token.repr()),
                Work::Node(Node::Tree(tree)) => {
                    out.push_str("Tree(");
                    out.push_str(&repr_str(tree.data));
                    out.push_str(", [");
                    stack.push(Work::Text("])"));
                    let children = tree.children.borrow();
                    for (index, child) in children.iter().enumerate().rev() {
                        stack.push(Work::Node(child.clone()));
                        if index > 0 {
                            stack.push(Work::Text(", "));
                        }
                    }
                }
            }
        }
        out
    }
}

fn regexes() -> &'static Vec<Option<Regex>> {
    static REGEXES: OnceLock<Vec<Option<Regex>>> = OnceLock::new();
    REGEXES.get_or_init(|| {
        TERMINALS
            .iter()
            .map(|(_, pattern, _)| {
                if pattern.is_empty() {
                    return None;
                }
                RegexBuilder::new(&format!("\\A(?:{pattern})"))
                    .backtrack_limit(50_000_000)
                    .build()
                    .ok()
            })
            .collect()
    })
}

/// `Scanner.match` at the start of `rest`: the terminal, after any `UnlessCallback`, and the match's length.
fn scan(lexer: usize, rest: &str) -> Option<(u16, usize)> {
    let regexes = regexes();
    for (terminal, unless) in *LEXERS.get(lexer)? {
        let Some(Some(regex)) = regexes.get(usize::from(*terminal)) else {
            continue;
        };
        if let Ok(Some(found)) = regex.find(rest) {
            let text = found.as_str();
            for embedded in *unless {
                if let Some(Some(whole)) = regexes.get(usize::from(*embedded))
                    && whole.find(text).ok().flatten().map(|m| m.end()) == Some(text.len())
                {
                    return Some((*embedded, text.len()));
                }
            }
            return Some((*terminal, text.len()));
        }
    }
    None
}

fn action(state: u16, symbol: u16) -> Option<i16> {
    let row = STATES.get(usize::from(state))?;
    row.binary_search_by_key(&symbol, |entry| entry.0)
        .ok()
        .map(|at| row[at].1)
}

fn end_symbol() -> u16 {
    (TERMINALS.len() - 1) as u16
}

/// `InteractiveParser.accepts`: the terminals a state can take, with the reductions each needs.
fn accepts(states: &[u16]) -> Vec<&'static str> {
    let mut accepted = Vec::new();
    let Some(&top) = states.last() else {
        return accepted;
    };
    let Some(row) = STATES.get(usize::from(top)) else {
        return accepted;
    };
    for (symbol, _) in *row {
        if usize::from(*symbol) >= TERMINALS.len() {
            continue;
        }
        let mut stack = states.to_vec();
        if try_feed(&mut stack, *symbol, *symbol == end_symbol()) {
            accepted.push(TERMINALS[usize::from(*symbol)].0);
        }
    }
    accepted
}

fn try_feed(stack: &mut Vec<u16>, symbol: u16, is_end: bool) -> bool {
    loop {
        let Some(&state) = stack.last() else {
            return false;
        };
        let Some(act) = action(state, symbol) else {
            return false;
        };
        if act >= 0 {
            return true;
        }
        let Some(rule) = RULES.get(usize::from((-act - 1) as u16)) else {
            return false;
        };
        stack.truncate(stack.len().saturating_sub(usize::from(rule.1)));
        let Some(&under) = stack.last() else {
            return false;
        };
        let Some(goto) = action(under, rule.0) else {
            return false;
        };
        stack.push(goto as u16);
        if is_end && goto as u16 == END_STATE {
            return true;
        }
    }
}

fn user_repr(name: &str) -> &str {
    TERMINALS.iter().find(|t| t.0 == name).map_or(name, |t| t.2)
}

/// `_format_expected`. Python's order is a set's, which changes each run, so these are sorted.
fn format_expected(mut expected: Vec<String>) -> String {
    expected.sort();
    format!("Expected one of: \n\t* {}\n", expected.join("\n\t* "))
}

fn context(chars: &[char], pos: usize) -> String {
    let before: String = chars[pos.saturating_sub(40)..pos].iter().collect();
    let after: String = chars[pos..(pos + 40).min(chars.len())].iter().collect();
    let before = before.rsplit('\n').next().unwrap_or("");
    let after = after.split('\n').next().unwrap_or("");
    let mut width = 0;
    for c in before.chars() {
        width = if c == '\t' {
            (width / 8 + 1) * 8
        } else if c == '\r' {
            0
        } else {
            width + 1
        };
    }
    format!("{before}{after}\n{}^\n", " ".repeat(width))
}

struct Counter {
    pos: usize,
    chars: usize,
    line: usize,
    column: usize,
    line_start: usize,
}

impl Counter {
    fn feed(&mut self, token: &str, kind: u16) {
        let length = token.chars().count();
        if NEWLINE_TERMINALS.contains(&kind) {
            let newlines = token.matches('\n').count();
            if newlines > 0 {
                self.line += newlines;
                let last = token.rfind('\n').unwrap_or(0);
                self.line_start = self.chars + token[..last].chars().count() + 1;
            }
        }
        self.pos += token.len();
        self.chars += length;
        self.column = self.chars - self.line_start + 1;
    }
}

/// One formula's tokens, each of which holds a tree node. Python would go on until memory ran out, and
/// raises what this raises.
const TOKEN_LIMIT: u32 = 4_000_000;

/// The kind of the error when the pass's clock ran out while parsing.
pub const OUT_OF_TIME: &str = "PassTimeout";

/// `Lark.parse(text)`: the tree of `start`, or the exception's type and message.
pub fn parse(text: &str, expired: &dyn Fn() -> bool) -> Result<Node, (&'static str, String)> {
    let mut states: Vec<u16> = vec![START_STATE];
    let mut values: Vec<Node> = Vec::new();
    let mut counter = Counter {
        pos: 0,
        chars: 0,
        line: 1,
        column: 1,
        line_start: 0,
    };
    let mut last: Option<Rc<Token>> = None;
    let mut tokens = 0u32;
    while counter.pos < text.len() {
        tokens = tokens.wrapping_add(1);
        if tokens.is_multiple_of(4096) && expired() {
            return Err((OUT_OF_TIME, String::new()));
        }
        if tokens > TOKEN_LIMIT {
            return Err(("MemoryError", String::new()));
        }
        let state = *states.last().unwrap_or(&START_STATE);
        let lexer = usize::from(LEXER_OF_STATE.get(usize::from(state)).copied().unwrap_or(0));
        let rest = &text[counter.pos..];
        let Some((kind, length)) = scan(lexer, rest) else {
            return Err(unexpected_characters(
                text,
                &counter,
                lexer,
                last.as_deref(),
                &states,
            ));
        };
        let matched = &rest[..length];
        if kind == IGNORE {
            counter.feed(matched, kind);
            continue;
        }
        let token = Token::new(kind, matched, counter.line, counter.column);
        counter.feed(matched, kind);
        last = Some(token.clone());
        feed(&mut states, &mut values, token, false)?;
    }
    let end = match &last {
        Some(token) => Token::new(end_symbol(), "", token.line, token.column),
        None => Token::new(end_symbol(), "", 1, 1),
    };
    feed(&mut states, &mut values, end, true)?;
    values
        .pop()
        .ok_or(("UnexpectedToken", "nothing parsed".to_owned()))
}

fn unexpected_characters(
    text: &str,
    counter: &Counter,
    lexer: usize,
    last: Option<&Token>,
    states: &[u16],
) -> (&'static str, String) {
    let allowed: Vec<String> = LEXERS[lexer]
        .iter()
        .map(|(terminal, _)| terminal)
        .filter(|terminal| **terminal != IGNORE)
        .map(|terminal| TERMINALS[usize::from(*terminal)].0.to_owned())
        .collect();
    let mut allowed = allowed;
    allowed.sort();
    allowed.dedup();
    if allowed.is_empty() {
        allowed.push("<END-OF-FILE>".to_owned());
    }
    let expected_names: Vec<String> = allowed.iter().map(|n| user_repr(n).to_owned()).collect();
    // the root lexer may know this text, and then it's an unexpected token
    let rest = &text[counter.pos..];
    if let Some((kind, length)) = scan(LEXERS.len() - 1, rest) {
        let token = Token::new(kind, &rest[..length], counter.line, counter.column);
        let history = last.map_or("None".to_owned(), Token::repr);
        // `self.accepts or self.expected`
        let accepted = accepts(states);
        let expected_names: Vec<String> = if accepted.is_empty() {
            expected_names
        } else {
            accepted.iter().map(|n| user_repr(n).to_owned()).collect()
        };
        return (
            "UnexpectedToken",
            format!(
                "Unexpected token {} at line {}, column {}.\n{}Previous tokens: [{history}]\n",
                token.repr(),
                token.line,
                token.column,
                format_expected(expected_names),
            ),
        );
    }
    let chars: Vec<char> = text.chars().collect();
    let pos = counter.chars;
    let mut message = format!(
        "No terminal matches '{}' in the current parser context, at line {} col {}\n\n{}",
        chars.get(pos).copied().unwrap_or(' '),
        counter.line,
        counter.column,
        context(&chars, pos),
    );
    message.push_str(&format_expected(expected_names));
    if let Some(token) = last {
        message.push_str(&format!("\nPrevious tokens: {}\n", token.repr()));
    }
    ("UnexpectedCharacters", message)
}

fn feed(
    states: &mut Vec<u16>,
    values: &mut Vec<Node>,
    token: Rc<Token>,
    is_end: bool,
) -> Result<(), (&'static str, String)> {
    loop {
        let state = *states.last().unwrap_or(&START_STATE);
        let Some(act) = action(state, token.kind) else {
            let mut expected = accepts(states);
            if expected.is_empty() {
                let row = STATES.get(usize::from(state)).copied().unwrap_or(&[]);
                expected = row
                    .iter()
                    .filter(|(symbol, _)| usize::from(*symbol) < TERMINALS.len())
                    .map(|(symbol, _)| TERMINALS[usize::from(*symbol)].0)
                    .collect();
            }
            return Err((
                "UnexpectedToken",
                format!(
                    "Unexpected token {} at line {}, column {}.\n{}",
                    token.repr(),
                    token.line,
                    token.column,
                    format_expected(expected.iter().map(|s| (*s).to_owned()).collect()),
                ),
            ));
        };
        if act >= 0 {
            states.push(act as u16);
            values.push(Node::Token(token));
            return Ok(());
        }
        let rule = &RULES[usize::from((-act - 1) as u16)];
        let size = usize::from(rule.1);
        let popped = values.split_off(values.len() - size);
        states.truncate(states.len() - size);
        let mut filtered: Vec<Node> = Vec::new();
        for (index, splice) in rule.3 {
            let child = popped[usize::from(*index)].clone();
            if *splice {
                if let Node::Tree(tree) = &child {
                    let mut spliced = tree.children.borrow_mut();
                    // a left-recursive list comes back here on every item, so this can't copy it
                    if filtered.is_empty() {
                        std::mem::swap(&mut filtered, &mut spliced);
                    } else {
                        filtered.append(&mut spliced);
                    }
                }
            } else {
                filtered.push(child);
            }
        }
        let value = if rule.2 && filtered.len() == 1 {
            filtered.remove(0)
        } else {
            let name = ORIGINS[usize::from(rule.0) - TERMINALS.len()];
            Node::Tree(Rc::new(Tree {
                data: name,
                children: RefCell::new(filtered),
            }))
        };
        let under = *states.last().unwrap_or(&START_STATE);
        let Some(goto) = action(under, rule.0) else {
            return Err(("UnexpectedToken", "no goto".to_owned()));
        };
        states.push(goto as u16);
        values.push(value);
        if is_end && goto as u16 == END_STATE {
            return Ok(());
        }
    }
}
