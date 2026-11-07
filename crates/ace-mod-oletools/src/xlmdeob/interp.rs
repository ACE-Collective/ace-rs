//! `XLMInterpreter` of XLMMacroDeobfuscator 0.2.7: it walks each formula's tree and works out what it can.
//!
//! The library is untyped and much of what it does on an odd macro is raise, in a handler, an exception
//! that ends the emulation and is printed. So this keeps its shape, handler for handler, with its values as
//! `Value` and its exceptions as `Raised`, including the unbound locals that some of its paths reach.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;

use super::lark::{self, Node, Tree};
use super::sheet::{
    Address, Cell, CellRef, Cells, SheetRef, abs_addr, column_index, column_name, parse_cell_addr,
    parse_cell_addr_value, parse_range_addr,
};
use super::value::{
    R, Raised, Value, attr_error, datetime_str, excel_date, float_to_int, index_error,
    integer_float_str, memory_error, parse_datetime, parse_float, parse_time, py_lower, py_round,
    raise, strip_quotes, unbound, unwrap_str_literal, wrap_str_literal,
};
use super::wrapper::{Names, OutRef, Wrapper};
use crate::py::repr_str;

/// The frames Python has before it runs out: its recursion limit less what the command stands on, which
/// is its `<module>`, `main`, `process_file` and this generator.
const RECURSION_LIMIT: usize = 1000;
pub const COMMAND_FRAMES: usize = 4;
/// The deepest lark goes while it parses: from `Lark.parse` to a terminal's match, or to a tree's node.
const PARSE_FRAMES: usize = 10;

/// One string. Python would go on until memory ran out, and raises what this raises.
const STRING_LIMIT: usize = 64 * 1024 * 1024;
/// Text written to cells, or cached formulas, over a whole pass. A macro's real ones are far short of it.
const STORED_LIMIT: usize = 512 * 1024 * 1024;
/// Cells copied when a branch's condition is unknown, over a whole pass.
const COPIED_LIMIT: usize = 64_000_000;
/// All of a macro's VirtualAllocs: Python's lists of the same size would be eight times this, and each
/// byte prints as two.
const MEMORY_LIMIT: i128 = 64 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    FullEvaluation,
    PartialEvaluation,
    Error,
    End,
    Branching,
    FullBranching,
    Ignored,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::FullEvaluation => "FullEvaluation",
            Status::PartialEvaluation => "PartialEvaluation",
            Status::Error => "Error",
            Status::End => "End",
            Status::Branching => "Branching",
            Status::FullBranching => "FullBranching",
            Status::Ignored => "IGNORED",
        }
    }
}

const JUMP_FUNCTIONS: &[&str] = &["GOTO", "RUN"];
const IMPORTANT_FUNCTIONS: &[&str] = &[
    "CALL", "FOPEN", "FWRITE", "FREAD", "REGISTER", "IF", "WHILE", "HALT", "CLOSE", "NEXT",
];

pub struct EvalResult {
    next_cell: Option<CellRef>,
    status: Status,
    value: Value,
    text: Option<String>,
    output_level: i32,
}

/// `EvalResult.__init__`, with `set_text`'s `str(data)` left to the caller.
fn result(
    next_cell: Option<CellRef>,
    status: Status,
    value: Value,
    text: Option<String>,
) -> EvalResult {
    EvalResult {
        next_cell,
        status,
        value,
        text,
        output_level: 0,
    }
}

fn is_digits_text(text: &str) -> Option<f64> {
    parse_float(text)
}

impl EvalResult {
    /// `get_text`, which stores a number's normal form back.
    fn get_text(&mut self, unwrap: bool) -> R<String> {
        let Some(text) = &self.text else {
            return Ok(String::new());
        };
        let mut text = text.clone();
        if let Some(number) = is_digits_text(&text) {
            text = if number.is_finite() && number == number.trunc() {
                integer_float_str(number)
            } else {
                super::value::float_str(number)
            };
            self.text = Some(text.clone());
        }
        Ok(if unwrap {
            unwrap_str_literal(&text)
        } else {
            text
        })
    }
}

fn text_value(value: Value) -> (Value, Option<String>) {
    let text = value.to_py_str();
    (value, Some(text))
}

/// `convert_ptree_to_str`: every token's text, in order. Iterative, as Python's RecursionError here is
/// counted by the frames around it.
pub fn ptree_str(node: &Node) -> String {
    let mut out = String::new();
    let mut stack = vec![node.clone()];
    while let Some(node) = stack.pop() {
        match node {
            Node::Token(token) => out.push_str(&token.text),
            Node::EmptyList => {}
            Node::Tree(tree) => {
                for child in tree.children.borrow().iter().rev() {
                    stack.push(child.clone());
                }
            }
        }
    }
    out
}

/// The height of a tree in Python frames, for `convert_ptree_to_str`'s recursion.
fn tree_height(node: &Node) -> usize {
    let mut deepest = 1;
    let mut stack = vec![(node.clone(), 1usize)];
    while let Some((node, depth)) = stack.pop() {
        deepest = deepest.max(depth);
        if let Node::Tree(tree) = node {
            for child in tree.children.borrow().iter() {
                stack.push((child.clone(), depth + 1));
            }
        }
    }
    deepest
}

fn data_of(node: &Node) -> Option<&'static str> {
    match node {
        Node::Tree(tree) => Some(tree.data),
        _ => None,
    }
}

fn child(tree: &Rc<Tree>, index: usize) -> R<Node> {
    tree.children
        .borrow()
        .get(index)
        .cloned()
        .map_or_else(index_error, Ok)
}

fn children_of(node: &Node) -> R<Vec<Node>> {
    match node {
        Node::Tree(tree) => Ok(tree.children.borrow().clone()),
        Node::Token(_) => attr_error("Token", "children"),
        Node::EmptyList => attr_error("list", "children"),
    }
}

fn check_size(text: &str) -> R<()> {
    if text.len() > STRING_LIMIT {
        return memory_error();
    }
    Ok(())
}

/// What the `+`, `-`, ... of two strs do, past the numeric cases.
fn str_operator(op: &str, left: &str, right: &str) -> R<Value> {
    let unsupported = |op: &str| {
        raise(
            "TypeError",
            format!("unsupported operand type(s) for {op}: 'str' and 'str'"),
        )
    };
    let by_chars = |a: &str, b: &str| a.chars().cmp(b.chars());
    use std::cmp::Ordering::{Greater, Less};
    Ok(match op {
        "+" => {
            let mut joined = String::with_capacity(left.len() + right.len());
            joined.push_str(left);
            joined.push_str(right);
            check_size(&joined)?;
            Value::string(joined)
        }
        "-" | "/" => return unsupported(op),
        "*" => {
            return raise(
                "TypeError",
                "can't multiply sequence by non-int of type 'str'",
            );
        }
        ">" => Value::Bool(by_chars(left, right) == Greater),
        "<" => Value::Bool(by_chars(left, right) == Less),
        "<>" => Value::Bool(left != right),
        "=" => Value::Bool(left == right),
        ">=" => Value::Bool(by_chars(left, right) != Less),
        "<=" => Value::Bool(by_chars(left, right) != Greater),
        _ => Value::None,
    })
}

enum FloatOp {
    Number(f64),
    Truth(bool),
}

fn float_operator(op: &str, left: f64, right: f64) -> R<FloatOp> {
    Ok(match op {
        "+" => FloatOp::Number(left + right),
        "-" => FloatOp::Number(left - right),
        "*" => FloatOp::Number(left * right),
        "/" => {
            if right == 0.0 {
                return raise("ZeroDivisionError", "division by zero");
            }
            FloatOp::Number(left / right)
        }
        ">" => FloatOp::Truth(left > right),
        "<" => FloatOp::Truth(left < right),
        "<>" => FloatOp::Truth(left != right),
        "=" => FloatOp::Truth(left == right),
        ">=" => FloatOp::Truth(left >= right),
        _ => FloatOp::Truth(left <= right),
    })
}

fn python_mod(left: f64, right: f64) -> R<f64> {
    if right == 0.0 {
        return raise("ZeroDivisionError", "division by zero");
    }
    let mut remainder = left % right;
    if remainder != 0.0 {
        if (right < 0.0) != (remainder < 0.0) {
            remainder += right;
        }
    } else {
        remainder = 0.0f64.copysign(right);
    }
    Ok(remainder)
}

fn convert_float(value: &Value) -> R<Value> {
    let Some(text) = value.as_text() else {
        return attr_error(value.type_name(), "lower");
    };
    let lower = py_lower(&text);
    if lower == "false" {
        Ok(Value::Int(0))
    } else if lower == "true" {
        Ok(Value::Int(1))
    } else {
        Ok(Value::Float(Value::str(&lower).to_float()?))
    }
}

fn number_lt(a: &Value, b: &Value) -> R<bool> {
    Ok(a.to_float()? < b.to_float()?)
}

fn truthy_number(value: &Option<Value>) -> bool {
    value.as_ref().is_some_and(Value::truthy)
}

struct WhileRecord {
    start_point: CellRef,
    status: bool,
    /// FOR.CELL's.
    iterator: Option<RangeIter>,
    has_iterator: bool,
}

struct RangeIter {
    sheet: Option<String>,
    from_col: Option<String>,
    to_col: Option<String>,
    start_row: Option<String>,
    end_row: Option<String>,
    rows: Option<(i128, i128)>,
    col: i128,
}

struct Frame {
    cell: CellRef,
    formula: Formula,
    cells: Cells,
    indent: i64,
    desc: &'static str,
}

#[derive(Clone)]
enum Formula {
    Text(Option<String>),
    Tree(Node),
}

/// What a step of `deobfuscate_macro` yields.
pub struct Step {
    pub cell: CellRef,
    pub status: Status,
    pub text: String,
    pub indent: i64,
}

struct Registered {
    name: String,
}

pub struct MemoryRecord {
    base: i128,
    size: i128,
    data: Vec<u8>,
}

/// Budget and clock, which copies of an interpreter share.
pub struct Limits {
    pub deadline: Option<Instant>,
    pub steps: u32,
    pub stored: usize,
    pub copied: usize,
    /// The frames under the emulation, which move where a deep macro hits RecursionError.
    pub base_frames: usize,
}

pub type LimitsRef = Rc<RefCell<Limits>>;

pub struct Interpreter {
    wrapper: Rc<Wrapper>,
    out: OutRef,
    limits: LimitsRef,
    formula_cache: Rc<RefCell<HashMap<String, Node>>>,
    defined_names: Names,
    auto_labels: Vec<Value>,
    branch_stack: Vec<Frame>,
    while_stack: Vec<WhileRecord>,
    function_call_stack: Vec<CellRef>,
    pub memory: Vec<MemoryRecord>,
    pub files: IndexMap<String, FileRecord>,
    registered: HashMap<String, Registered>,
    indent_level: i64,
    indent_current_line: bool,
    invoke_interpreter: bool,
    first_unknown_cell: Option<String>,
    unsuccessful: HashSet<(Option<String>, String)>,
    selected_range: Option<(Address, Address, Option<Address>)>,
    active_cell: Option<CellRef>,
    ignore_processing: bool,
    remove_current_formula: bool,
    iserror_count: i32,
    iserror_loc: Option<CellRef>,
    iserror_val: bool,
    now_count: i64,
    depth: usize,
}

impl MemoryRecord {
    pub fn describe(&self) -> (i128, i128, String) {
        let mut hex = String::with_capacity(self.data.len() * 2);
        for byte in &self.data {
            hex.push_str(&format!("{byte:02x}"));
        }
        (self.base, self.size, hex)
    }
}

pub struct FileRecord {
    pub access: Value,
    pub content: String,
}

const MAX_ISERROR_LOOPCOUNT: i32 = 10;

/// `unicode_to_latin1_map`.
fn unicode_to_latin1(value: i128) -> Option<i128> {
    Some(match value {
        8364 => 128,
        8218 => 130,
        402 => 131,
        8222 => 132,
        8230 => 133,
        8224 => 134,
        8225 => 135,
        710 => 136,
        8240 => 137,
        352 => 138,
        8249 => 139,
        338 => 140,
        381 => 142,
        8216 => 145,
        8217 => 146,
        8220 => 147,
        8221 => 148,
        8226 => 149,
        8211 => 150,
        8212 => 151,
        732 => 152,
        8482 => 153,
        353 => 154,
        8250 => 155,
        339 => 156,
        382 => 158,
        376 => 159,
        _ => return None,
    })
}

const GET_WINDOW_CONF: &str = include_str!("get_window.conf");
const GET_WORKSPACE_CONF: &str = include_str!("get_workspace.conf");

/// A conf file's line for `number`, as `get_window` and `get_workspace` read it: stripped, and blank
/// lines absent. `numbers` turns a line that's a number into an int.
fn conf_value(conf: &str, number: i128, numbers: bool) -> Value {
    if number < 1 {
        return Value::None;
    }
    let Some(line) = conf.split_inclusive('\n').nth(number as usize - 1) else {
        return Value::None;
    };
    let line = line.trim_matches(crate::py::is_space);
    if line.is_empty() {
        return Value::None;
    }
    if numbers && let Some(number) = parse_float(line) {
        return match float_to_int(number) {
            Ok(number) => Value::Int(number),
            Err(_) => Value::str(line),
        };
    }
    Value::str(line)
}

type Args = [Node];

fn arg(arguments: &Args, index: usize) -> R<&Node> {
    arguments.get(index).map_or_else(index_error, Ok)
}

fn int_of_row(row: &Option<String>) -> R<i128> {
    match row {
        Some(row) => Value::str(row).to_int(),
        None => raise(
            "TypeError",
            "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'",
        ),
    }
}

fn index_of_col(col: &Option<String>) -> R<i128> {
    match col {
        Some(col) => Ok(column_index(col)),
        None => raise("TypeError", "'NoneType' object is not reversible"),
    }
}

fn concat_address(col: &Option<String>, row: impl std::fmt::Display) -> R<String> {
    match col {
        Some(col) => Ok(format!("{col}{row}")),
        None => raise(
            "TypeError",
            "unsupported operand type(s) for +: 'NoneType' and 'str'",
        ),
    }
}

fn parse_error<T>(kind: &'static str, message: String) -> R<T> {
    raise(kind, message)
}

impl Interpreter {
    pub fn new(wrapper: Rc<Wrapper>, out: OutRef, limits: LimitsRef) -> R<Interpreter> {
        let defined_names = wrapper.get_defined_names()?;
        let depth = limits.borrow().base_frames;
        Ok(Interpreter {
            wrapper,
            out,
            limits,
            formula_cache: Rc::new(RefCell::new(HashMap::new())),
            defined_names,
            auto_labels: Vec::new(),
            branch_stack: Vec::new(),
            while_stack: Vec::new(),
            function_call_stack: Vec::new(),
            memory: Vec::new(),
            files: IndexMap::new(),
            registered: HashMap::new(),
            indent_level: 0,
            indent_current_line: false,
            invoke_interpreter: false,
            first_unknown_cell: None,
            unsuccessful: HashSet::new(),
            selected_range: None,
            active_cell: None,
            ignore_processing: false,
            remove_current_formula: false,
            iserror_count: 0,
            iserror_loc: None,
            iserror_val: false,
            now_count: 0,
            depth,
        })
    }

    fn print(&self, line: &str) -> R<()> {
        self.out.borrow_mut().print(line)
    }

    /// The pass's clock and what the interpreter has stored so far.
    fn tick(&self) -> R<()> {
        let mut limits = self.limits.borrow_mut();
        limits.steps = limits.steps.wrapping_add(1);
        if limits.steps.is_multiple_of(256)
            && let Some(deadline) = limits.deadline
            && Instant::now() >= deadline
        {
            return Err(Raised::Timeout);
        }
        Ok(())
    }

    fn store(&self, bytes: usize) -> R<()> {
        let mut limits = self.limits.borrow_mut();
        limits.stored += bytes;
        if limits.stored > STORED_LIMIT {
            return memory_error();
        }
        Ok(())
    }

    /// A Python call: past the recursion limit it raises, as Python's own does.
    fn frame<T>(&mut self, count: usize, call: impl FnOnce(&mut Self) -> R<T>) -> R<T> {
        if self.depth + count > RECURSION_LIMIT {
            return raise("RecursionError", "maximum recursion depth exceeded");
        }
        self.depth += count;
        let answer = call(self);
        self.depth -= count;
        answer
    }

    fn check_tree_height(&self, node: &Node) -> R<()> {
        if self.depth + tree_height(node) > RECURSION_LIMIT {
            return raise("RecursionError", "maximum recursion depth exceeded");
        }
        Ok(())
    }

    fn ptree(&self, node: &Node) -> R<String> {
        if matches!(node, Node::EmptyList) {
            return attr_error("list", "children");
        }
        self.check_tree_height(node)?;
        Ok(ptree_str(node))
    }

    fn parse(&self, text: &str) -> R<Node> {
        if self.depth + PARSE_FRAMES > RECURSION_LIMIT {
            return raise("RecursionError", "maximum recursion depth exceeded");
        }
        let deadline = self.limits.borrow().deadline;
        let expired = move || deadline.is_some_and(|at| Instant::now() >= at);
        lark::parse(text, &expired).or_else(|(kind, message)| {
            if kind == lark::OUT_OF_TIME {
                return Err(Raised::Timeout);
            }
            parse_error(kind, message)
        })
    }

    fn macrosheets(&self) -> R<IndexMap<String, SheetRef>> {
        self.wrapper.get_macrosheets()
    }

    fn get_formula_cell(
        &self,
        sheet: &SheetRef,
        col: &Option<String>,
        row: &Option<String>,
    ) -> R<Option<CellRef>> {
        let row = int_of_row(row)?;
        let mut current = row;
        let Some(col) = col else {
            return raise(
                "TypeError",
                "unsupported operand type(s) for +: 'NoneType' and 'str'",
            );
        };
        let cells = sheet.cells.borrow().clone();
        let cells = cells.borrow();
        loop {
            if let Some(cell) = cells.get(&format!("{col}{current}"))
                && cell.borrow().formula.is_some()
            {
                return Ok(Some(cell.clone()));
            }
            if current - row < 10000 {
                current += 1;
            } else {
                return Ok(None);
            }
        }
    }

    fn range_parts(node: &Node) -> R<(Node, Node)> {
        if let Node::Tree(tree) = node
            && tree.data == "range"
        {
            let children = tree.children.borrow();
            if let (Some(first), Some(last)) = (children.first(), children.last()) {
                return Ok((first.clone(), last.clone()));
            }
        }
        // (None, None), and get_cell_addr on None
        attr_error("NoneType", "data")
    }

    fn get_cell_addr(&mut self, current: &CellRef, node: &Node) -> R<Address> {
        self.frame(1, |this| this.get_cell_addr_inner(current, node))
    }

    fn get_cell_addr_inner(&mut self, current: &CellRef, node: &Node) -> R<Address> {
        let current_sheet = current.borrow().sheet_name();
        let cell_node = match node {
            Node::Token(token) => {
                let value = token.value.borrow().clone();
                let Some(text) = value.as_text() else {
                    return attr_error(value.type_name(), "lower");
                };
                let label = py_lower(&text);
                let names = self.wrapper.get_defined_names()?;
                let found = names.borrow().get(&label).cloned();
                if let Some(name_val) = found {
                    if let Value::Node(tree @ Node::Tree(_)) = &name_val {
                        return self.get_cell_addr(current, tree);
                    }
                    return parse_cell_addr_value(&name_val);
                }
                let stripped = strip_quotes(&label).to_owned();
                let found = names.borrow().get(&stripped).cloned();
                if let Some(name_val) = found {
                    return parse_cell_addr_value(&name_val);
                }
                if label.chars().count() > 1 && label.starts_with('"') && label.ends_with('"') {
                    let root = self.parse(&format!("={stripped}"))?;
                    let first = children_of(&root)?;
                    let first = first.first().map_or_else(index_error, Ok)?.clone();
                    return self.get_cell_addr(current, &first);
                }
                return Ok((None, None, None));
            }
            Node::EmptyList => return attr_error("list", "data"),
            Node::Tree(tree) => {
                if tree.data == "defined_name" {
                    let label = match child(tree, 2)? {
                        Node::Token(token) => token.text.clone(),
                        _ => String::new(),
                    };
                    let formula = self.wrapper.get_defined_name(&label, true)?;
                    let Some(formula) = formula.as_text() else {
                        return raise(
                            "TypeError",
                            format!(
                                "can only concatenate str (not \"{}\") to str",
                                formula.type_name()
                            ),
                        );
                    };
                    let parsed = self.parse(&format!("={formula}"))?;
                    let first = children_of(&parsed)?;
                    let first = first.first().map_or_else(index_error, Ok)?.clone();
                    if data_of(&first) == Some("range") {
                        let (start, _) = Self::range_parts(&first)?;
                        children_of(&start)?
                            .first()
                            .map_or_else(index_error, Ok)?
                            .clone()
                    } else {
                        children_of(&first)?
                            .first()
                            .map_or_else(index_error, Ok)?
                            .clone()
                    }
                } else {
                    child(tree, 0)?
                }
            }
        };
        let cell = match &cell_node {
            Node::Tree(tree) => tree.clone(),
            Node::Token(_) => return attr_error("Token", "data"),
            Node::EmptyList => return attr_error("list", "data"),
        };
        let parts = cell.children.borrow().clone();
        match cell.data {
            "a1_notation_cell" => {
                let token_text = |node: &Node| match node {
                    Node::Token(token) => token.text.clone(),
                    _ => String::new(),
                };
                let address = if parts.len() == 2 {
                    format!("'{}'!{}", token_text(&parts[0]), token_text(&parts[1]))
                } else {
                    parts.first().map(token_text).unwrap_or_default()
                };
                let (mut sheet, col, row) = parse_cell_addr(&address);
                if sheet.is_none() && col.is_some() {
                    sheet = Some(current_sheet);
                }
                Ok((sheet, col, row))
            }
            "r1c1_notation_cell" => {
                let (current_col, current_row) = {
                    let borrowed = current.borrow();
                    (index_of_col(&borrowed.column)?, int_of_row(&borrowed.row)?)
                };
                let mut res_sheet = None;
                let mut res_row: Option<i128> = None;
                let mut res_col: Option<i128> = None;
                let mut last_seen: Option<char> = None;
                for part in &parts {
                    let Node::Token(token) = part else {
                        return attr_error("Tree", "type");
                    };
                    let value = token.value.borrow().clone();
                    if token.kind_name() == "NAME" {
                        res_sheet = Some(value.to_py_str());
                    } else if value.is_float() {
                        let number = float_to_int(value.to_float()?)?;
                        match last_seen {
                            Some('r') => res_row = Some(number),
                            Some(_) => res_col = Some(number),
                            None => return unbound("last_seen"),
                        }
                    } else if value.to_py_str().starts_with('[') {
                        let text = value.to_py_str();
                        let inner: String = {
                            let chars: Vec<char> = text.chars().collect();
                            chars[1..chars.len().saturating_sub(1).max(1)]
                                .iter()
                                .collect()
                        };
                        let number = Value::str(&inner).to_int()?;
                        match last_seen {
                            Some('r') => res_row = Some(current_row + number),
                            Some(_) => res_col = Some(current_col + number),
                            None => return unbound("last_seen"),
                        }
                    } else if token.text.to_lowercase() == "r" {
                        last_seen = Some('r');
                        res_row = Some(current_row);
                    } else if token.text.to_lowercase() == "c" {
                        last_seen = Some('c');
                        res_col = Some(current_col);
                    } else {
                        return raise("Exception", "Cell addresss, Syntax Error");
                    }
                }
                if res_sheet.is_none() {
                    res_sheet = Some(current_sheet);
                }
                let Some(col) = res_col else {
                    return raise(
                        "TypeError",
                        "'>' not supported between instances of 'NoneType' and 'int'",
                    );
                };
                Ok((
                    res_sheet,
                    Some(column_name(col)),
                    Some(res_row.map_or("None".to_owned(), |r| r.to_string())),
                ))
            }
            _ => raise("Exception", "Cell addresss, Syntax Error"),
        }
    }

    fn get_cell(
        &self,
        sheet_name: &Option<String>,
        col: &Option<String>,
        row: impl std::fmt::Display,
    ) -> R<Option<CellRef>> {
        let Some(sheet_name) = sheet_name else {
            // None is in neither dict, whichever sheets exist
            self.macrosheets()?;
            self.wrapper.get_worksheets()?;
            return Ok(None);
        };
        let sheets = self.macrosheets()?;
        if let Some(sheet) = sheets.get(sheet_name) {
            return Ok(sheet.cell(&concat_address(col, row)?));
        }
        let sheets = self.wrapper.get_worksheets()?;
        if let Some(sheet) = sheets.get(sheet_name) {
            return Ok(sheet.cell(&concat_address(col, row)?));
        }
        Ok(None)
    }

    fn get_worksheet_cell(
        &self,
        sheet_name: &Option<String>,
        col: &Option<String>,
        row: impl std::fmt::Display,
    ) -> R<Option<CellRef>> {
        let sheets = self.wrapper.get_worksheets()?;
        if let Some(name) = sheet_name
            && let Some(sheet) = sheets.get(name)
        {
            return Ok(sheet.cell(&concat_address(col, row)?));
        }
        Ok(None)
    }

    fn set_cell(
        &self,
        sheet_name: &Option<String>,
        col: &str,
        row: &str,
        text: &str,
        set_value_only: bool,
    ) -> R<()> {
        let sheets = self.macrosheets()?;
        let Some(sheet) = sheet_name.as_ref().and_then(|name| sheets.get(name)) else {
            return Ok(());
        };
        // and what a new cell costs, or a range of empty strings is free
        self.store(text.len() + col.len() + row.len() + 256)?;
        let address = format!("{col}{row}");
        let cells = sheet.cells.borrow().clone();
        let existing = cells.borrow().get(&address).cloned();
        let cell = match existing {
            Some(cell) => cell,
            None => {
                let mut new_cell = Cell::new(sheet);
                new_cell.column = Some(col.to_owned());
                new_cell.row = Some(row.to_owned());
                let new_cell = Rc::new(RefCell::new(new_cell));
                cells.borrow_mut().insert(address, new_cell.clone());
                new_cell
            }
        };
        let text = unwrap_str_literal(text);
        let mut cell = cell.borrow_mut();
        if !set_value_only {
            cell.formula = if text.starts_with('=') {
                Some(text.clone())
            } else {
                None
            };
        }
        cell.value = Value::string(text);
        Ok(())
    }

    fn get_window(number: i128) -> Value {
        conf_value(GET_WINDOW_CONF, number, true)
    }

    fn get_workspace(number: i128) -> Value {
        conf_value(GET_WORKSPACE_CONF, number, false)
    }

    fn evaluate_formula(
        &mut self,
        current: &CellRef,
        name: &str,
        arguments: &Args,
        interactive: bool,
        destination_arg: usize,
        set_value_only: bool,
    ) -> R<EvalResult> {
        if matches!(arguments.first(), Some(Node::EmptyList)) {
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::Bool(false),
                Some(format!("{name}()")),
            ));
        }
        let (source, destination) = if destination_arg == 1 {
            (arg(arguments, 0)?, arg(arguments, 1)?)
        } else {
            (arg(arguments, 1)?, arg(arguments, 0)?)
        };
        let mut src = self.evaluate_parse_tree(current, source, interactive)?;
        // the destination, which is a tree, a Token, a str or anything a defined name holds
        let mut destination = Value::Node(destination.clone());
        if let Value::Node(Node::Token(token)) = &destination {
            let found = self.wrapper.get_defined_name(&token.text, true)?;
            destination = match found {
                Value::List(items) => items
                    .first()
                    .cloned()
                    .unwrap_or(Value::List(Rc::new(Vec::new()))),
                other => other,
            };
        }
        if let Value::Str(text) = &destination {
            let parsed = self.parse(&format!("={text}"))?;
            let first = children_of(&parsed)?
                .first()
                .map_or_else(index_error, Ok)?
                .clone();
            destination = Value::Node(first);
        }
        let mut start: Option<Address> = None;
        let mut end: Option<Address> = None;
        let mut destination_str: Option<String> = None;
        if let Value::Node(Node::Tree(tree)) = &destination {
            let mut tree = tree.clone();
            if tree.data == "defined_name" || tree.data == "name" {
                let label = match child(&tree, 2)? {
                    Node::Token(token) => token.text.clone(),
                    _ => String::new(),
                };
                let formula = self.wrapper.get_defined_name(&label, true)?;
                let next = match &formula {
                    Value::Node(Node::Tree(found)) => Node::Tree(found.clone()),
                    other => {
                        let Some(text) = other.as_text() else {
                            return raise(
                                "TypeError",
                                format!(
                                    "can only concatenate str (not \"{}\") to str",
                                    other.type_name()
                                ),
                            );
                        };
                        let parsed = self.parse(&format!("={text}"))?;
                        children_of(&parsed)?
                            .first()
                            .map_or_else(index_error, Ok)?
                            .clone()
                    }
                };
                match next {
                    Node::Tree(found) => tree = found,
                    Node::Token(_) => return attr_error("Token", "data"),
                    Node::EmptyList => return attr_error("list", "data"),
                }
            }
            let node = Node::Tree(tree.clone());
            if tree.data == "concat_expression" || tree.data == "function_call" {
                let mut res = self.evaluate_parse_tree(current, &node, interactive)?;
                let address = if let Value::Tuple(items) = &res.value
                    && items.len() == 3
                {
                    let part = |at: usize| match &items[at] {
                        Value::None => None,
                        other => Some(other.to_py_str()),
                    };
                    destination_str = Some(format!(
                        "'{}'!{}{}",
                        items[0].to_py_str(),
                        items[1].to_py_str(),
                        items[2].to_py_str()
                    ));
                    (part(0), part(1), part(2))
                } else {
                    let Some(text) = res.text.take() else {
                        return attr_error("NoneType", "strip");
                    };
                    let parsed = parse_cell_addr(&text);
                    destination_str = Some(text);
                    parsed
                };
                start = Some(address.clone());
                end = Some(address);
            } else {
                if tree.data == "range" {
                    let first = child(&tree, 0)?;
                    let last = child(&tree, 2)?;
                    start = Some(self.get_cell_addr(current, &first)?);
                    end = Some(self.get_cell_addr(current, &last)?);
                } else {
                    let address = self.get_cell_addr(current, &node)?;
                    start = Some(address.clone());
                    end = Some(address);
                }
                destination_str = Some(self.ptree(&node)?);
            }
        }
        src.get_text(true)?;
        let (Some(start), Some(end)) = (start, end) else {
            return unbound("dst_start_row");
        };
        let (from_row, to_row) = (int_of_row(&start.2)?, int_of_row(&end.2)?);
        let (from_col, to_col) = (index_of_col(&start.1)?, index_of_col(&end.1)?);
        let full = src.status == Status::FullEvaluation;
        let value_text = src.value.to_py_str();
        check_size(&value_text)?;
        let mut row = from_row;
        while row <= to_row {
            self.tick()?;
            let mut col = from_col;
            while col <= to_col {
                self.tick()?;
                let name = column_name(col);
                let key = (start.0.clone(), format!("{name}{row}"));
                if full {
                    self.unsuccessful.remove(&key);
                    self.set_cell(
                        &start.0,
                        &name,
                        &row.to_string(),
                        &value_text,
                        set_value_only,
                    )?;
                } else {
                    self.store(64)?;
                    self.unsuccessful.insert(key);
                }
                col += 1;
            }
            row += 1;
        }
        let Some(destination_str) = destination_str else {
            return unbound("destination_str");
        };
        let src_text = src.get_text(false)?;
        let text = if destination_arg == 1 {
            format!("{name}({src_text},{destination_str})")
        } else {
            format!("{name}({destination_str},{src_text})")
        };
        Ok(result(None, src.status, Value::Int(0), Some(text)))
    }

    fn evaluate_argument_list(
        &mut self,
        current: &CellRef,
        name: &str,
        arguments: &Args,
    ) -> R<EvalResult> {
        self.frame(1, |this| this.argument_list(current, name, arguments))
    }

    fn argument_list(&mut self, current: &CellRef, name: &str, arguments: &Args) -> R<EvalResult> {
        let mut args = String::new();
        for argument in arguments {
            if !matches!(argument, Node::EmptyList) {
                let mut evaluated = self.evaluate_parse_tree(current, argument, false)?;
                args.push_str(&evaluated.get_text(false)?);
                args.push(',');
                check_size(&args)?;
            }
        }
        let text = format!("={name}({})", args.trim_matches(','));
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn evaluate_function(
        &mut self,
        current: &CellRef,
        root: &Rc<Tree>,
        interactive: bool,
    ) -> R<EvalResult> {
        let root_node = Node::Tree(root.clone());
        let function_name = child(root, 0)?;
        let literal = match &function_name {
            Node::Token(token) => unwrap_str_literal(&token.text),
            other => other.repr(),
        };
        if let Node::Tree(tree) = &function_name
            && tree.data == "function_call"
        {
            let mut inner = self.evaluate_parse_tree(current, &function_name, false)?;
            if inner.status != Status::FullEvaluation {
                let text = self.ptree(&root_node)?;
                return Ok(result(
                    inner.next_cell,
                    inner.status,
                    Value::Int(0),
                    Some(text),
                ));
            }
            inner.text = Some(self.ptree(&root_node)?);
            return Ok(inner);
        }
        if let Some(registered) = self.registered.get(&literal) {
            let Node::Token(token) = &function_name else {
                return attr_error("Tree", "update");
            };
            let updated = token.with_value(&registered.name);
            root.children.borrow_mut()[0] = Node::Token(updated);
            return self.frame(1, |this| this.evaluate_function(current, root, interactive));
        }
        if data_of(&function_name) == Some("cell") {
            self.function_call_stack.push(current.clone());
            return self.goto_handler(
                std::slice::from_ref(&function_name),
                current,
                interactive,
                &root_node,
            );
        }
        let mut resolved = Value::Node(function_name.clone());
        let lower = py_lower(&literal);
        let held = self.defined_names.borrow().get(&lower).cloned();
        if let Some(held) = held {
            resolved = self.name_as_cell(&held)?.unwrap_or(held);
        }
        if let Value::Node(Node::Tree(tree)) = &resolved
            && tree.data == "defined_name"
        {
            let last = tree.children.borrow().last().cloned();
            let Some(Node::Token(last)) = last else {
                return index_error();
            };
            let label = last.value.borrow().to_py_str();
            let held = self.defined_names.borrow().get(&py_lower(&label)).cloned();
            if let Some(held) = held {
                resolved = match self.name_as_cell(&held)? {
                    Some(found) => found,
                    None => match self.defined_names.borrow().get(&lower) {
                        Some(found) => found.clone(),
                        None => return raise("KeyError", repr_str(&lower)),
                    },
                };
            }
        }
        if let Value::Node(node @ Node::Tree(tree)) = &resolved
            && tree.data == "cell"
        {
            self.function_call_stack.push(current.clone());
            return self.goto_handler(std::slice::from_ref(node), current, interactive, &root_node);
        }
        if self.ignore_processing && literal != "NEXT" {
            return Ok(result(
                None,
                Status::Ignored,
                Value::Int(0),
                Some(String::new()),
            ));
        }
        let mut arguments = Vec::new();
        let arglist = child(root, 2)?;
        for item in children_of(&arglist)? {
            if let Node::Tree(tree) = &item {
                match tree.children.borrow().first() {
                    Some(first) => arguments.push(first.clone()),
                    None => arguments.push(Node::EmptyList),
                }
            }
        }
        let mut evaluated = self.frame(1, |this| {
            this.dispatch(&literal, &arguments, current, interactive, &root_node)
        })?;
        evaluated.output_level = if JUMP_FUNCTIONS.contains(&literal.as_str()) {
            0
        } else if IMPORTANT_FUNCTIONS.contains(&literal.as_str()) {
            2
        } else {
            1
        };
        Ok(evaluated)
    }

    /// `parse('=' + name)` when it's a cell, for a call through a defined name.
    fn name_as_cell(&self, held: &Value) -> R<Option<Value>> {
        let Some(text) = held.as_text() else {
            return Ok(None);
        };
        match lark::parse(&format!("={text}"), &|| false) {
            Ok(parsed) => {
                let first = children_of(&parsed).ok().and_then(|c| c.first().cloned());
                match first {
                    Some(node) if data_of(&node) == Some("cell") => Ok(Some(Value::Node(node))),
                    _ => Ok(None),
                }
            }
            Err(_) => Ok(None),
        }
    }

    fn dispatch(
        &mut self,
        name: &str,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        match name {
            "END.IF" => {
                self.indent_level -= 1;
                self.indent_current_line = true;
                Ok(result(
                    None,
                    Status::FullEvaluation,
                    Value::str("END.IF"),
                    Some("END.IF".to_owned()),
                ))
            }
            "FORMULA.FILL" | "FORMULA.ARRAY" | "FORMULA" | "SET.VALUE" => {
                let set_value = name == "SET.VALUE";
                let destination = if set_value { 2 } else { 1 };
                self.frame(1, |this| {
                    this.evaluate_formula(cell, name, args, i, destination, set_value)
                })
            }
            "GET.CELL" => self.get_cell_handler(args, cell, i, root),
            "GET.DOCUMENT" => self.get_document_handler(args, cell, i),
            "GET.WINDOW" => self.get_window_handler(args, cell, i, root),
            "GET.WORKSPACE" => self.get_workspace_handler(args, cell, i, root),
            "ON.TIME" => self.on_time_handler(args, cell, i, root),
            "SET.NAME" => self.set_name_handler(args, cell, i, root),
            "ACTIVE.CELL" => self.active_cell_handler(cell, i, root),
            "APP.MAXIMIZE" => {
                let (value, text) = text_value(Value::Bool(true));
                Ok(result(None, Status::FullEvaluation, value, text))
            }
            "ABS" => self.abs_handler(args, cell, i, root),
            "ABSREF" => self.absref_handler(args, cell, i, root),
            "ADDRESS" => self.address_handler(args, cell, i),
            "AND" => self.and_or_handler(args, cell, i, true),
            "OR" => self.and_or_handler(args, cell, i, false),
            "CALL" => self.call_handler(args, cell, i),
            "CHAR" => self.char_handler(args, cell, i, root),
            "CLOSE" | "HALT" => {
                let text = self.ptree(root)?;
                self.indent_level -= 1;
                Ok(result(None, Status::End, Value::str(&text), Some(text)))
            }
            "CODE" => self.code_handler(args, cell, i),
            "CONCATENATE" => self.concatenate_handler(args, cell, i),
            "COUNTA" => self.counta_handler(args, cell, i),
            "COUNT" => {
                let (value, text) = text_value(Value::Int(args.len() as i128));
                Ok(result(None, Status::FullEvaluation, value, text))
            }
            "DAY" => self.day_handler(args, cell, i, root),
            "DEFINE.NAME" => self.define_name_handler(args, cell, i, root),
            "DIRECTORY" => {
                let text = "C:\\Users\\user\\Documents";
                Ok(result(
                    None,
                    Status::FullEvaluation,
                    Value::str(text),
                    Some(text.to_owned()),
                ))
            }
            "ERROR" => Ok(result(
                None,
                Status::FullEvaluation,
                Value::Int(0),
                Some(self.ptree(root)?),
            )),
            "FILES" => self.files_handler(args, cell, i),
            "FOPEN" => self.fopen_handler(args, cell, i),
            "FOR.CELL" => self.forcell_handler(args, cell, i, root),
            "FSIZE" => self.fsize_handler(args, cell, i),
            "FWRITE" => self.fwrite_handler(args, cell, i, ""),
            "FWRITELN" => self.fwrite_handler(args, cell, i, "\r\n"),
            "GOTO" => self.goto_handler(args, cell, i, root),
            "INDEX" => self.index_handler(args, cell, i, root),
            "HLOOKUP" => self.hlookup_handler(args, cell, i),
            "IF" => self.if_handler(args, cell, i, root),
            "INDIRECT" => self.indirect_handler(args, cell, i),
            "INT" => self.int_handler(args, cell, i),
            "ISERROR" => self.iserror_handler(args, cell, i),
            "ISNUMBER" => self.is_number_handler(args, cell, i),
            "LEN" => self.len_handler(args, cell, i, root),
            "MAX" => self.min_max_handler(args, cell, i, root, false),
            "MIN" => self.min_max_handler(args, cell, i, root, true),
            "MOD" => self.mod_handler(args, cell, i),
            "MID" => self.mid_handler(args, cell, i),
            "SQRT" => self.sqrt_handler(args, cell, i, root),
            "NEXT" => self.next_handler(),
            "NOT" => self.not_handler(args, cell, i),
            "NOW" => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0.0, |d| d.as_secs_f64());
                let value = excel_date(now + (self.now_count * 2) as f64);
                self.now_count += 1;
                let (value, text) = text_value(Value::Float(value));
                Ok(result(None, Status::FullEvaluation, value, text))
            }
            "OFFSET" => self.offset_handler(args, cell, i, root),
            "PRODUCT" => self.product_handler(args, cell, i, root),
            "QUOTIENT" => self.quotient_handler(args, cell, i),
            "RANDBETWEEN" => self.randbetween_handler(args, cell, i),
            "REGISTER" => self.register_handler(args, cell, i, root),
            "REGISTER.ID" => self.registerid_handler(args, cell, i, root),
            "RETURN" => self.return_handler(args, cell, i),
            "ROUND" => self.round_handler(args, cell, i),
            "ROUNDUP" => self.roundup_handler(args, cell, i),
            "RUN" => self.run_handler(args, cell, root),
            "ROWS" => self.rows_handler(args, cell, i, root),
            "SEARCH" => self.search_handler(args, cell, i),
            "SELECT" => self.select_handler(args, cell, i, root),
            "SUM" => self.sum_handler(args, cell, i),
            "T" => self.t_handler(args, cell, i),
            "TEXT" => self.text_handler(args, cell, i),
            "TRUNC" => self.trunc_handler(args, cell, i, root),
            "VALUE" => self.value_handler(args, cell, i, root),
            "WHILE" => self.while_handler(args, cell, i, root),
            "Kernel32.VirtualAlloc" => self.virtual_alloc_handler(args, cell, i, root),
            "Kernel32.WriteProcessMemory" => self.write_process_memory_handler(args, cell, i, root),
            "Kernel32.RtlCopyMemory" => self.rtl_copy_memory_handler(args, cell, i, root),
            "_xlfn.ARABIC" => self.arabic_handler(args, cell, i, root),
            // Python calls this one directly, where `dispatch`'s frame stands for a handler's
            _ => self.argument_list(cell, name, args),
        }
    }

    fn and_or_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        is_and: bool,
    ) -> R<EvalResult> {
        let mut value = is_and;
        let mut status = Status::FullEvaluation;
        for argument in args {
            let evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            if evaluated.status == Status::FullEvaluation {
                let text = py_lower(&unwrap_str_literal(&evaluated.value.to_py_str()));
                if is_and && text != "true" {
                    value = false;
                    break;
                }
                if !is_and && text == "true" {
                    value = true;
                    break;
                }
            } else {
                status = Status::PartialEvaluation;
                if is_and {
                    value = false;
                }
                break;
            }
        }
        let (value, text) = text_value(Value::Bool(value));
        Ok(result(None, status, value, text))
    }

    fn hlookup_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let second = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let third = self.evaluate_parse_tree(cell, arg(args, 2)?, i)?;
        let fourth = self.evaluate_parse_tree(cell, arg(args, 3)?, i)?;
        let Some(text) = &first.text else {
            return attr_error("NoneType", "strip");
        };
        let mut pattern = strip_quotes(text).to_owned();
        if pattern == "*" {
            pattern = ".*".to_owned();
        }
        if fourth.value.is_str("FALSE") {
            let Some(range_text) = &second.text else {
                return raise(
                    "TypeError",
                    "expected string or bytes-like object, got 'NoneType'",
                );
            };
            let Some((sheet, start_col, start_row, end_col, end_row)) =
                parse_range_addr(range_text)
            else {
                return raise(
                    "ValueError",
                    "not enough values to unpack (expected 5, got 3)",
                );
            };
            let start_col = column_index(&start_col);
            let end_col = column_index(&end_col);
            let start_row = Value::str(&start_row).to_int()? + third.value.to_int()? - 1;
            let end_row = Value::str(&end_row).to_int()?;
            let regex = match fancy_regex::Regex::new(&format!("\\A(?:{pattern})")) {
                Ok(regex) => regex,
                Err(error) => return raise("PatternError", error.to_string()),
            };
            let current_sheet = Some(cell.borrow().sheet_name());
            let mut row = start_row;
            while row <= end_row {
                self.tick()?;
                let mut col = start_col;
                while col <= end_col {
                    let name = Some(column_name(col));
                    let found = if sheet.is_some() {
                        self.get_worksheet_cell(&sheet, &name, row)?
                    } else {
                        self.get_cell(&current_sheet, &name, row)?
                    };
                    if let Some(found) = found {
                        let value = found.borrow().value.clone();
                        let Some(text) = value.as_text() else {
                            return raise(
                                "TypeError",
                                format!(
                                    "expected string or bytes-like object, got '{}'",
                                    value.type_name()
                                ),
                            );
                        };
                        if regex.is_match(&text).unwrap_or(false) {
                            let string = value.to_py_str();
                            return Ok(result(None, Status::FullEvaluation, value, Some(string)));
                        }
                    }
                    col += 1;
                }
                row += 1;
            }
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::str(""),
                Some(String::new()),
            ));
        }
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(""),
            Some(String::new()),
        ))
    }

    fn not_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut value = true;
        let mut status = Status::FullEvaluation;
        if evaluated.status == Status::FullEvaluation {
            if py_lower(&unwrap_str_literal(&evaluated.value.to_py_str())) == "true" {
                value = false;
            }
        } else {
            status = Status::PartialEvaluation;
        }
        let (value, text) = text_value(Value::Bool(value));
        Ok(result(None, status, value, text))
    }

    fn code_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut value: i128 = 0;
        let mut status = Status::FullEvaluation;
        if evaluated.status == Status::FullEvaluation {
            let Some(text) = &evaluated.text else {
                return raise("TypeError", "'NoneType' object is not subscriptable");
            };
            if let Some(first) = text.chars().next() {
                value = i128::from(u32::from(first));
                if value > 256
                    && let Some(mapped) = unicode_to_latin1(value)
                {
                    value = mapped;
                }
            }
        } else {
            status = Status::PartialEvaluation;
        }
        let (value, text) = text_value(Value::Int(value));
        Ok(result(None, status, value, text))
    }

    fn sum_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut status = Status::FullEvaluation;
        let mut value = Value::Int(0);
        for argument in args {
            let evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            value = Value::Float(value.to_float()? + evaluated.value.to_float()?);
            status = evaluated.status;
        }
        let (value, text) = text_value(value);
        Ok(result(None, status, value, text))
    }

    fn randbetween_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let low = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let high = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        if low.status != Status::FullEvaluation || high.status != Status::FullEvaluation {
            return unbound("status");
        }
        let from = float_to_int(low.value.to_float()?)?;
        let to = float_to_int(high.value.to_float()?)?;
        if from > to {
            return raise(
                "ValueError",
                format!("empty range in randrange({from}, {})", to + 1),
            );
        }
        // a value Python draws at random: a clock's bits do here
        let span = (to - from + 1) as u128;
        let noise = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let value = from + (u128::from(noise) % span) as i128;
        let (value, text) = text_value(Value::Int(value));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn text_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let second = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let mut value = Value::Int(0);
        let mut status = Status::PartialEvaluation;
        if first.status == Status::FullEvaluation {
            let Some(text) = &second.text else {
                return attr_error("NoneType", "strip");
            };
            if Value::str(strip_quotes(text)).to_int()? == 0 {
                status = Status::FullEvaluation;
                value = Value::Int(first.value.to_int()?);
            }
        }
        let (value, text) = text_value(value);
        Ok(result(None, status, value, text))
    }

    fn active_cell_handler(&mut self, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let Some(active) = self.active_cell.clone() else {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(&text),
                Some(text),
            ));
        };
        let (formula, value) = {
            let active = active.borrow();
            (active.formula.clone(), active.value.clone())
        };
        let (val, status) = match formula.filter(|f| !f.is_empty()) {
            Some(formula) => {
                let tree = self.parse(&formula)?;
                let evaluated = self.evaluate_parse_tree(cell, &tree, i)?;
                (evaluated.value, evaluated.status)
            }
            None => (value, Status::FullEvaluation),
        };
        let (value, text) = text_value(val);
        Ok(result(None, status, value, text))
    }

    fn get_cell_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        if args.len() != 2 {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(""),
                Some(text),
            ));
        }
        let first = self.evaluate_parse_tree(cell, &args[0], i)?;
        let (sheet, col, row) = self.get_cell_addr(cell, &args[1])?;
        let mut type_id = first.value.clone();
        if type_id.is_float() {
            type_id = Value::Int(float_to_int(type_id.to_float()?)?);
        }
        let sheet = sheet.unwrap_or_else(|| cell.borrow().sheet_name());
        if first.status != Status::FullEvaluation {
            return unbound("return_val");
        }
        let (data, _, not_implemented) =
            self.wrapper
                .get_cell_info(&sheet, col.as_deref(), row.as_deref(), &type_id)?;
        if not_implemented {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(""),
                Some(text),
            ));
        }
        let text = match &data {
            Value::None => None,
            other => Some(other.to_py_str()),
        };
        Ok(result(None, Status::FullEvaluation, data, text))
    }

    fn set_name_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let label = py_lower(&unwrap_str_literal(&self.ptree(arg(args, 0)?)?));
        let second = arg(args, 1)?;
        if data_of(second) == Some("cell") {
            let text2 = self.ptree(second)?;
            self.wrapper
                .get_defined_names()?
                .borrow_mut()
                .insert(label.clone(), Value::Node(second.clone()));
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::Int(0),
                Some(format!("SET.NAME({label},{text2})")),
            ));
        }
        let mut evaluated = self.evaluate_parse_tree(cell, second, i)?;
        if evaluated.status == Status::FullEvaluation {
            let text2 = evaluated.get_text(true)?;
            self.store(text2.len())?;
            let stored = match &evaluated.value {
                Value::Cell(found) => Value::Cell(found.clone()),
                _ => Value::str(&text2),
            };
            self.wrapper
                .get_defined_names()?
                .borrow_mut()
                .insert(label.clone(), stored);
            Ok(result(
                None,
                Status::FullEvaluation,
                Value::Int(0),
                Some(format!("SET.NAME({label},{text2})")),
            ))
        } else {
            let text = self.ptree(root)?;
            Ok(result(
                None,
                evaluated.status,
                Value::str(&text),
                Some(text),
            ))
        }
    }

    fn get_workspace_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        if args.len() == 1 {
            let mut evaluated = self.evaluate_parse_tree(cell, &args[0], i)?;
            if evaluated.status == Status::FullEvaluation {
                let text = evaluated.get_text(false)?;
                if let Some(number) = parse_float(&text) {
                    let parameter = Self::get_workspace(float_to_int(number)?);
                    return Ok(result(
                        None,
                        Status::FullEvaluation,
                        parameter,
                        Some(format!("GET.WORKSPACE({text})")),
                    ));
                }
            }
        }
        let text = self.ptree(root)?;
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn get_window_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        if args.len() == 1 {
            let mut evaluated = self.evaluate_parse_tree(cell, &args[0], i)?;
            let text = evaluated.get_text(false)?;
            if evaluated.status == Status::FullEvaluation
                && let Some(number) = parse_float(&text)
            {
                let number = float_to_int(number)?;
                let parameter = Self::get_window(number);
                let shown = match &parameter {
                    Value::None => None,
                    other => Some(other.to_py_str()),
                };
                let mut value = parameter;
                if number == 1 || number == 30 {
                    value = Value::string(format!(
                        "[{}]{}",
                        self.wrapper.get_workbook_name()?,
                        cell.borrow().sheet_name()
                    ));
                }
                return Ok(result(None, Status::FullEvaluation, value, shown));
            }
            let shown = format!("GET.WINDOW({text})");
            return Ok(result(
                None,
                evaluated.status,
                Value::str(&shown),
                Some(shown),
            ));
        }
        let text = self.ptree(root)?;
        Ok(result(None, Status::Error, Value::str(&text), Some(text)))
    }

    fn get_document_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut status = Status::Error;
        let mut value = String::new();
        if evaluated.value.is_int()? {
            status = Status::PartialEvaluation;
            let number = evaluated.value.to_int()?;
            if number == 76 {
                value = format!(
                    "[{}]{}",
                    self.wrapper.get_workbook_name()?,
                    cell.borrow().sheet_name()
                );
                status = Status::FullEvaluation;
            } else if number == 88 {
                value = self.wrapper.get_workbook_name()?;
                status = Status::FullEvaluation;
            }
        }
        Ok(result(None, status, Value::str(&value), Some(value)))
    }

    fn on_time_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        if args.len() != 2 {
            return unbound("return_val");
        }
        let _first = self.evaluate_parse_tree(cell, &args[0], i)?;
        let (sheet, col, row) = self.get_cell_addr(cell, &args[1])?;
        let sheets = self.macrosheets()?;
        let found = sheet.as_ref().and_then(|name| sheets.get(name));
        let Some(found) = found else {
            let text = self.ptree(root)?;
            return Ok(result(None, Status::Error, Value::str(&text), Some(text)));
        };
        let next = self.get_formula_cell(found, &col, &row)?;
        let text = self.ptree(root)?;
        Ok(result(
            next,
            Status::FullEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn concatenate_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut text = String::new();
        for argument in args {
            let mut evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            text.push_str(&evaluated.get_text(true)?);
            check_size(&text)?;
        }
        let wrapped = wrap_str_literal(&Value::str(&text), false)?;
        Ok(result(
            None,
            Status::FullEvaluation,
            Value::string(text),
            Some(wrapped),
        ))
    }

    /// A DAY's date is never a `datetime`, as no handler makes one, so `guess_day` can't run and isn't ported.
    /// NOW()'s float takes the path that sets no value, and so does a partial argument.
    fn day_handler(&mut self, args: &Args, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status != Status::FullEvaluation {
            self.ptree(root)?;
            return unbound("return_val");
        }
        if evaluated.value.is_float() {
            return unbound("return_val");
        }
        unbound("status")
    }

    fn value_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let value = unwrap_str_literal(&evaluated.value.to_py_str());
        let as_value = Value::str(&value);
        if as_value.is_int()? {
            let (number, text) = text_value(Value::Int(as_value.to_int()?));
            return Ok(result(None, Status::FullEvaluation, number, text));
        }
        if let Some(number) = parse_float(&value) {
            let (number, text) = text_value(Value::Float(number));
            return Ok(result(None, Status::FullEvaluation, number, text));
        }
        let text = self.ptree(root)?;
        Ok(result(None, Status::Error, Value::Int(0), Some(text)))
    }

    fn if_handler(&mut self, args: &Args, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let address = cell.borrow().local_address()?;
        for frame in &self.branch_stack {
            if frame.cell.borrow().local_address()? == address {
                let text = format!("[[LOOP]]: {}", self.ptree(root)?);
                return Ok(result(None, Status::End, Value::Int(0), Some(text)));
            }
        }
        if args.len() != 3 {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::Int(0),
                Some(text),
            ));
        }
        let condition = self.evaluate_parse_tree(cell, &args[0], i)?;
        let mut truth = condition.value.clone();
        if let Some(parsed) = truth.strtobool() {
            truth = Value::Bool(parsed);
        } else if truth.is_int()? {
            truth = Value::Bool(truth.to_int()? != 0);
        }
        let sheet = cell.borrow().sheet.clone();
        let Some(sheet) = sheet else {
            return attr_error("NoneType", "cells");
        };
        let live = sheet.cells.borrow().clone();
        let status;
        if condition.status == Status::FullEvaluation {
            let (branch, desc) = if truth.truthy() {
                (&args[1], "[TRUE]")
            } else {
                (&args[2], "[FALSE]")
            };
            if matches!(branch, Node::EmptyList) {
                status = Status::FullEvaluation;
            } else {
                self.branch_stack.push(Frame {
                    cell: cell.clone(),
                    formula: Formula::Tree(branch.clone()),
                    cells: live,
                    indent: self.indent_level,
                    desc,
                });
                status = Status::Branching;
            }
        } else {
            let saved = self.deep_copy_cells(&live)?;
            self.branch_stack.push(Frame {
                cell: cell.clone(),
                formula: Formula::Tree(args[2].clone()),
                cells: saved,
                indent: self.indent_level,
                desc: "[FALSE]",
            });
            self.branch_stack.push(Frame {
                cell: cell.clone(),
                formula: Formula::Tree(args[1].clone()),
                cells: live,
                indent: self.indent_level,
                desc: "[TRUE]",
            });
            status = Status::FullBranching;
        }
        let text = self.ptree(root)?;
        Ok(result(None, status, Value::Int(0), Some(text)))
    }

    /// `copy.deepcopy(sheet.cells)`: new cells, with the same sheet.
    fn deep_copy_cells(&self, cells: &Cells) -> R<Cells> {
        let cells = cells.borrow();
        {
            let mut limits = self.limits.borrow_mut();
            limits.copied += cells.len();
            if limits.copied > COPIED_LIMIT {
                return memory_error();
            }
        }
        let mut copy = IndexMap::with_capacity(cells.len());
        for (address, cell) in cells.iter() {
            let cell = cell.borrow();
            copy.insert(
                address.clone(),
                Rc::new(RefCell::new(Cell {
                    sheet: cell.sheet.clone(),
                    column: cell.column.clone(),
                    row: cell.row.clone(),
                    formula: cell.formula.clone(),
                    value: cell.value.clone(),
                    style: cell.style.clone(),
                })),
            );
        }
        Ok(Rc::new(RefCell::new(copy)))
    }

    fn mid_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let text_arg = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let base_arg = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let length_arg = self.evaluate_parse_tree(cell, arg(args, 2)?, i)?;
        if text_arg.status == Status::FullEvaluation
            && base_arg.status == Status::FullEvaluation
            && length_arg.status == Status::FullEvaluation
            && base_arg.value.is_float()
            && length_arg.value.is_float()
        {
            let base = float_to_int(base_arg.value.to_float()?)? - 1;
            let length = float_to_int(length_arg.value.to_float()?)?;
            let value = unwrap_str_literal(&text_arg.value.to_py_str());
            let picked = py_slice(&value, base, base + length);
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::str(&picked),
                Some(picked),
            ));
        }
        let text = format!(
            "MID({},{},{})",
            self.ptree(&args[0])?,
            self.ptree(&args[1])?,
            self.ptree(&args[2])?
        );
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(""),
            Some(text),
        ))
    }

    fn min_max_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
        is_min: bool,
    ) -> R<EvalResult> {
        let mut best: Option<Value> = None;
        for argument in args {
            let evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            if evaluated.status == Status::FullEvaluation {
                let current = convert_float(&evaluated.value)?;
                let better = match &best {
                    Some(held) if held.truthy() => {
                        if is_min {
                            number_lt(&current, held)?
                        } else {
                            number_lt(held, &current)?
                        }
                    }
                    _ => true,
                };
                if better {
                    best = Some(current);
                }
            } else {
                best = None;
                break;
            }
        }
        if truthy_number(&best) {
            let (value, text) = text_value(best.unwrap_or_default());
            return Ok(result(None, Status::FullEvaluation, value, text));
        }
        let text = self.ptree(root)?;
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn product_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let mut total: Option<Value> = None;
        for argument in args {
            let evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            if evaluated.status == Status::FullEvaluation {
                let current = convert_float(&evaluated.value)?;
                total = Some(match &total {
                    Some(held) if held.truthy() => match (held, &current) {
                        (Value::Int(a), Value::Int(b)) => Value::Int(a.saturating_mul(*b)),
                        _ => Value::Float(held.to_float()? * current.to_float()?),
                    },
                    _ => current,
                });
            } else {
                total = None;
                break;
            }
        }
        if truthy_number(&total) {
            let (value, text) = text_value(total.unwrap_or_default());
            return Ok(result(None, Status::FullEvaluation, value, text));
        }
        let text = self.ptree(root)?;
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn mod_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let second = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        if first.status != Status::FullEvaluation || second.status != Status::FullEvaluation {
            return unbound("status");
        }
        let number = python_mod(first.value.to_float()?, second.value.to_float()?)?;
        let (value, text) = text_value(Value::Float(number));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn sqrt_handler(&mut self, args: &Args, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status == Status::FullEvaluation {
            let number = evaluated.value.to_float()?;
            if number < 0.0 {
                return raise(
                    "ValueError",
                    format!(
                        "expected a nonnegative input, got {}",
                        super::value::float_str(number)
                    ),
                );
            }
            if number.is_nan() {
                return raise("ValueError", "cannot convert float NaN to integer");
            }
            if number.is_infinite() {
                return raise("OverflowError", "cannot convert float infinity to integer");
            }
            let (value, text) = text_value(Value::Int(number.sqrt().floor() as i128));
            return Ok(result(None, Status::FullEvaluation, value, text));
        }
        let text = self.ptree(root)?;
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn goto_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        _i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let (sheet, col, row) = self.get_cell_addr(cell, arg(args, 0)?)?;
        let sheets = self.macrosheets()?;
        let mut next = None;
        let status = match sheet.as_ref().and_then(|name| sheets.get(name)) {
            Some(found) => {
                next = self.get_formula_cell(found, &col, &row)?;
                Status::FullEvaluation
            }
            None => Status::Error,
        };
        let text = self.ptree(root)?;
        Ok(result(next, status, Value::Int(0), Some(text)))
    }

    fn call_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut status = Status::FullEvaluation;
        let mut texts = Vec::new();
        for argument in args {
            let mut evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            if evaluated.status != Status::FullEvaluation {
                status = evaluated.status;
            }
            texts.push(evaluated.get_text(false)?);
        }
        let text = format!("CALL({})", texts.join(","));
        check_size(&text)?;
        Ok(result(None, status, Value::Int(0), Some(text)))
    }

    fn is_number_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status == Status::FullEvaluation {
            let text = evaluated.text.clone().map_or(Value::None, Value::string);
            let number = i128::from(text.is_int()? || text.is_float());
            let (value, shown) = text_value(Value::Int(number));
            return Ok(result(None, evaluated.status, value, shown));
        }
        let shown = format!("ISNUMBER({})", evaluated.get_text(false)?);
        Ok(result(None, evaluated.status, Value::Int(1), Some(shown)))
    }

    fn search_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut second = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        if first.status == Status::FullEvaluation && second.status == Status::FullEvaluation {
            let needle = unwrap_str_literal(&first.value.to_py_str());
            let haystack = unwrap_str_literal(&second.value.to_py_str());
            let (lower_hay, lower_needle) = (py_lower(&haystack), py_lower(&needle));
            return Ok(match lower_hay.find(&lower_needle) {
                Some(at) => {
                    let (value, text) =
                        text_value(Value::Int(lower_hay[..at].chars().count() as i128));
                    result(None, Status::FullEvaluation, value, text)
                }
                None => result(
                    None,
                    Status::FullEvaluation,
                    Value::None,
                    Some(String::new()),
                ),
            });
        }
        let text = format!(
            "SEARCH({},{})",
            first.get_text(false)?,
            second.get_text(false)?
        );
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::Int(0),
            Some(text),
        ))
    }

    fn round_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let second = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        if first.status != Status::FullEvaluation || second.status != Status::FullEvaluation {
            return unbound("status");
        }
        let digits = float_to_int(second.value.to_float()?)?;
        let (value, text) = text_value(Value::Float(py_round(first.value.to_float()?, digits)));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn roundup_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if first.status != Status::FullEvaluation {
            return unbound("status");
        }
        let number = first.value.to_float()?;
        let integer = float_to_int(number.ceil())?;
        let (value, text) = text_value(Value::Int(integer));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn char_handler(&mut self, args: &Args, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status != Status::FullEvaluation {
            let text = format!("CHAR({})", evaluated.text.as_deref().unwrap_or("None"));
            return Ok(result(
                evaluated.next_cell,
                Status::PartialEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        let mut value = evaluated.text.clone().map_or(Value::None, Value::string);
        match &evaluated.value {
            Value::List(_) => return raise("TypeError", "unhashable type: 'list'"),
            other => {
                if let Some(key) = other.as_text()
                    && let Some(held) = self.defined_names.borrow().get(&key)
                {
                    value = match held {
                        Value::Cell(found) => found.borrow().value.clone(),
                        Value::Node(Node::Token(token)) => token.value.borrow().clone(),
                        other => return attr_error(other.type_name(), "value"),
                    };
                }
            }
        }
        let number = value.to_float()?;
        if (0.0..=255.0).contains(&number) {
            let code = number.trunc() as u32;
            let text = char::from_u32(code).map(String::from).unwrap_or_default();
            return Ok(result(
                evaluated.next_cell,
                Status::FullEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        let text = self.ptree(root)?;
        Ok(result(
            evaluated.next_cell,
            Status::Error,
            Value::str(&text),
            Some(text),
        ))
    }

    fn t_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut value = Value::str("");
        let mut status = Status::PartialEvaluation;
        if evaluated.status == Status::FullEvaluation {
            if let Value::Tuple(items) = &evaluated.value
                && items.len() == 3
            {
                let part = |at: usize| match &items[at] {
                    Value::None => None,
                    other => Some(other.to_py_str()),
                };
                let found = self.get_cell(&part(0), &part(1), items[2].to_py_str())?;
                let Some(found) = found else {
                    return attr_error("NoneType", "value");
                };
                value = found.borrow().value.clone();
            } else if !evaluated.value.is_str("TRUE") && !evaluated.value.is_str("FALSE") {
                value = Value::string(evaluated.value.to_py_str());
            }
            status = Status::FullEvaluation;
        }
        let shown = wrap_str_literal(&Value::string(value.to_py_str()), true)?;
        Ok(result(evaluated.next_cell, status, value, Some(shown)))
    }

    fn int_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut number = 0;
        let mut status = Status::PartialEvaluation;
        if evaluated.status == Status::FullEvaluation {
            let text = py_lower(&evaluated.value.to_py_str());
            if text == "true" {
                number = 1;
            } else if text != "false" {
                number = evaluated.value.to_int()?;
            }
            status = Status::FullEvaluation;
        }
        let (value, text) = text_value(Value::Int(number));
        Ok(result(evaluated.next_cell, status, value, text))
    }

    fn run_handler(&mut self, args: &Args, cell: &CellRef, root: &Node) -> R<EvalResult> {
        if !(1..=2).contains(&args.len()) {
            let text = self.ptree(root)?;
            return Ok(result(None, Status::Error, Value::Int(1), Some(text)));
        }
        let (sheet, col, row) = self.get_cell_addr(cell, &args[0])?;
        let sheets = self.macrosheets()?;
        if let Some(name) = &sheet
            && let Some(found) = sheets.get(name)
        {
            let next = self.get_formula_cell(found, &col, &row)?;
            let place = format!(
                "{name}!{}{}",
                col.as_deref().unwrap_or("None"),
                row.as_deref().unwrap_or("None")
            );
            let text = if args.len() == 1 {
                format!("RUN({place})")
            } else {
                format!("RUN({place}, {})", self.ptree(&args[1])?)
            };
            return Ok(result(
                next,
                Status::FullEvaluation,
                Value::Int(0),
                Some(text),
            ));
        }
        let text = self.ptree(root)?;
        Ok(result(None, Status::Error, Value::Int(0), Some(text)))
    }

    fn select_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let mut status = Status::PartialEvaluation;
        let _range = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let base = self.active_cell.clone().unwrap_or_else(|| cell.clone());
        if args.len() == 2 {
            let (sheet, col, row) = self.get_cell_addr(&base, &args[1])?;
            if sheet.as_deref().is_some_and(|name| !name.is_empty()) {
                self.active_cell = self.get_cell(&sheet, &col, row.as_deref().unwrap_or("None"))?;
                status = Status::FullEvaluation;
            }
        } else if matches!(args[0], Node::Token(_)) {
            // nothing to select
        } else if data_of(&args[0]) == Some("range") {
            let Some(selected) = &self.selected_range else {
                return raise("TypeError", "'NoneType' object is not subscriptable");
            };
            let Some((sheet, col, row)) = selected.2.clone() else {
                return raise("TypeError", "cannot unpack non-iterable NoneType object");
            };
            if sheet.as_deref().is_some_and(|name| !name.is_empty()) {
                self.active_cell = self.get_cell(&sheet, &col, row.as_deref().unwrap_or("None"))?;
                status = Status::FullEvaluation;
            }
        } else if data_of(&args[0]) == Some("cell") {
            let (sheet, col, row) = self.get_cell_addr(&base, &args[0])?;
            if sheet.as_deref().is_some_and(|name| !name.is_empty()) {
                self.active_cell = self.get_cell(&sheet, &col, row.as_deref().unwrap_or("None"))?;
                status = Status::FullEvaluation;
            }
        } else if matches!(args[0], Node::EmptyList) {
            return attr_error("list", "data");
        }
        let text = self.ptree(root)?;
        Ok(result(None, status, Value::Int(0), Some(text)))
    }

    fn forcell_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let variable = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let (start_node, end_node) = Self::range_parts(arg(args, 1)?)?;
        let start = self.get_cell_addr(cell, &start_node)?;
        let mut end = self.get_cell_addr(cell, &end_node)?;
        if start.0 != end.0 {
            end = (start.0.clone(), end.1, end.2);
        }
        if args.len() >= 3 {
            let _skip = self.evaluate_parse_tree(cell, &args[2], i)?;
        }
        let name = py_lower(&unwrap_str_literal(&variable.value.to_py_str()));
        let reuse = self
            .while_stack
            .last()
            .is_some_and(|top| Rc::ptr_eq(&top.start_point, cell));
        if !reuse {
            self.while_stack.push(WhileRecord {
                start_point: cell.clone(),
                status: true,
                iterator: Some(RangeIter {
                    sheet: start.0.clone(),
                    from_col: start.1.clone(),
                    to_col: end.1.clone(),
                    rows: None,
                    start_row: start.2.clone(),
                    end_row: end.2.clone(),
                    col: 0,
                }),
                has_iterator: true,
            });
        }
        // `next(iterator)` in a bare `except:`, which any failure in the generator ends
        let next = self.next_in_range();
        match next {
            Ok(Some(found)) => {
                self.defined_names
                    .borrow_mut()
                    .insert(name, Value::Cell(found));
            }
            Ok(None) | Err(Raised::Exception { .. }) => {
                if let Some(top) = self.while_stack.last_mut() {
                    top.status = false;
                }
            }
            Err(other) => return Err(other),
        }
        self.indent_level += 1;
        let text = self.ptree(root)?;
        Ok(result(
            None,
            Status::FullEvaluation,
            Value::Int(0),
            Some(text),
        ))
    }

    /// The generator `iterate_range`, a step at a time.
    fn next_in_range(&mut self) -> R<Option<CellRef>> {
        loop {
            self.tick()?;
            let Some(iterator) = self
                .while_stack
                .last_mut()
                .and_then(|top| top.iterator.as_mut())
            else {
                return Ok(None);
            };
            let (row, to_row) = match iterator.rows {
                Some(rows) => rows,
                None => {
                    let rows = (
                        int_of_row(&iterator.start_row)?,
                        int_of_row(&iterator.end_row)?,
                    );
                    iterator.rows = Some(rows);
                    iterator.col = index_of_col(&iterator.from_col)?;
                    rows
                }
            };
            if row > to_row {
                return Ok(None);
            }
            let to_col = index_of_col(&iterator.to_col)?;
            if iterator.col > to_col {
                iterator.rows = Some((row + 1, to_row));
                iterator.col = index_of_col(&iterator.from_col)?;
                continue;
            }
            let (sheet, col) = (iterator.sheet.clone(), iterator.col);
            iterator.col += 1;
            if let Some(found) = self.get_cell(&sheet, &Some(column_name(col)), row)? {
                return Ok(Some(found));
            }
        }
    }

    fn while_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let mut record = WhileRecord {
            start_point: cell.clone(),
            status: false,
            iterator: None,
            has_iterator: false,
        };
        let condition = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let status = condition.status;
        let mut text = String::new();
        if condition.status == Status::FullEvaluation {
            let shown = condition.value.to_py_str();
            if py_lower(&shown) == "true" {
                record.status = true;
            }
            text = format!("{} -> [{shown}]", self.ptree(root)?);
        }
        if text.is_empty() {
            text = self.ptree(root)?;
        }
        let keep_going = record.status;
        self.while_stack.push(record);
        if !keep_going {
            self.ignore_processing = true;
        }
        self.indent_level += 1;
        Ok(result(None, status, Value::Int(0), Some(text)))
    }

    fn next_handler(&mut self) -> R<EvalResult> {
        let mut status = Status::FullEvaluation;
        let mut next = None;
        if self.indent_level == self.while_stack.len() as i64 {
            self.ignore_processing = false;
            if let Some(top) = self.while_stack.pop() {
                if top.status {
                    next = Some(top.start_point.clone());
                }
                if top.has_iterator {
                    self.while_stack.push(top);
                }
            }
            self.indent_level = if self.indent_level > 0 {
                self.indent_level - 1
            } else {
                0
            };
            self.indent_current_line = true;
        }
        if next.is_none() {
            status = Status::Ignored;
        }
        Ok(result(next, status, Value::Int(0), Some("NEXT".to_owned())))
    }

    fn len_handler(&mut self, args: &Args, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let mut evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status == Status::FullEvaluation {
            let length = evaluated.get_text(true)?.chars().count();
            let (value, text) = text_value(Value::Int(length as i128));
            return Ok(result(None, Status::FullEvaluation, value, text));
        }
        let text = self.ptree(root)?;
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn define_name_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let name_arg = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if name_arg.status != Status::FullEvaluation {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        let value_arg = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let name_text = name_arg.text.as_deref().unwrap_or("None");
        let name = py_lower(&unwrap_str_literal(name_text));
        let stored = if value_arg.value.is_int()? {
            Value::Int(value_arg.value.to_int()?)
        } else if value_arg.value.is_float() {
            Value::Float(value_arg.value.to_float()?)
        } else {
            value_arg.value.clone()
        };
        self.defined_names
            .borrow_mut()
            .insert(name.clone(), stored.clone());
        let text = format!(
            "DEFINE.NAME({},{})",
            wrap_str_literal(&Value::str(&name), false)?,
            stored.to_py_str()
        );
        Ok(result(None, Status::FullEvaluation, stored, Some(text)))
    }

    fn index_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let array = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if array.status != Status::FullEvaluation {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        let index_arg = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let value = if let Value::List(items) = &array.value {
            let index = float_to_int(index_arg.value.to_float()?)? - 1;
            let length = items.len() as i128;
            let at = if index < 0 { index + length } else { index };
            if at < 0 || at >= length {
                return index_error();
            }
            items[at as usize].clone()
        } else {
            let range = unwrap_str_literal(&array.value.to_py_str());
            let parsed = parse_range_addr(&range);
            let index = float_to_int(index_arg.value.to_float()?)? - 1;
            let Some(parsed) = parsed else {
                return raise(
                    "TypeError",
                    "float() argument must be a string or a real number, not 'NoneType'",
                );
            };
            let row = float_to_int(Value::str(&parsed.2).to_float()?)? + index;
            let sheet = parsed
                .0
                .clone()
                .or_else(|| Some(cell.borrow().sheet_name()));
            match self.get_cell(&sheet, &Some(parsed.1.clone()), row)? {
                Some(found) => Value::Cell(found),
                None => Value::None,
            }
        };
        let (value, text) = text_value(value);
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn rows_handler(&mut self, args: &Args, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status != Status::FullEvaluation {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        let number = if let Value::List(items) = &evaluated.value {
            items.len() as i128
        } else {
            let range = unwrap_str_literal(&evaluated.value.to_py_str());
            let Some(parsed) = parse_range_addr(&range) else {
                return raise("IndexError", "tuple index out of range");
            };
            Value::str(&parsed.4).to_int()? - Value::str(&parsed.2).to_int()? + 1
        };
        let (value, text) = text_value(Value::Int(number));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn counta_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let Some(text) = &evaluated.text else {
            return raise(
                "TypeError",
                "expected string or bytes-like object, got 'NoneType'",
            );
        };
        let Some((sheet, start_col, start_row, end_col, end_row)) = parse_range_addr(text) else {
            return raise(
                "ValueError",
                "not enough values to unpack (expected 5, got 3)",
            );
        };
        let (from_row, to_row) = (
            Value::str(&start_row).to_int()?,
            Value::str(&end_row).to_int()?,
        );
        let (from_col, to_col) = (column_index(&start_col), column_index(&end_col));
        let current_sheet = Some(cell.borrow().sheet_name());
        let mut count = 0;
        let mut row = from_row;
        while row <= to_row {
            self.tick()?;
            let mut col = from_col;
            while col <= to_col {
                let name = Some(column_name(col));
                let found = if sheet.is_some() {
                    self.get_worksheet_cell(&sheet, &name, row)?
                } else {
                    self.get_cell(&current_sheet, &name, row)?
                };
                if let Some(found) = found
                    && !found.borrow().value.is_str("")
                {
                    count += 1;
                }
                col += 1;
            }
            row += 1;
        }
        let (value, text) = text_value(Value::Int(count));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn trunc_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status != Status::FullEvaluation {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        let number = if evaluated.value.is_str("TRUE") {
            1
        } else if evaluated.value.is_str("FALSE") {
            0
        } else {
            float_to_int(evaluated.value.to_float()?)?
        };
        let (value, text) = text_value(Value::Int(number));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn quotient_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let second = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if first.status != Status::FullEvaluation || second.status != Status::FullEvaluation {
            return unbound("return_val");
        }
        // both are the first argument, as the library has it
        let value = match (&first.value, &second.value) {
            (Value::Int(a), Value::Int(b)) => {
                if *b == 0 {
                    return raise("ZeroDivisionError", "division by zero");
                }
                Value::Int(a.div_euclid(*b))
            }
            (Value::Float(a), Value::Float(b)) => {
                if *b == 0.0 {
                    return raise("ZeroDivisionError", "division by zero");
                }
                Value::Float((a / b).floor())
            }
            (a, b) => {
                return raise(
                    "TypeError",
                    format!(
                        "unsupported operand type(s) for //: '{}' and '{}'",
                        a.type_name(),
                        b.type_name()
                    ),
                );
            }
        };
        let (value, text) = text_value(value);
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn abs_handler(&mut self, args: &Args, cell: &CellRef, i: bool, root: &Node) -> R<EvalResult> {
        let evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if evaluated.status != Status::FullEvaluation {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        let number = if evaluated.value.is_str("TRUE") {
            Value::Int(1)
        } else if evaluated.value.is_str("FALSE") {
            Value::Int(0)
        } else {
            Value::Float(evaluated.value.to_float()?.abs())
        };
        let (value, text) = text_value(number);
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn absref_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let reference = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let second = arg(args, 1)?;
        if reference.status == Status::FullEvaluation && data_of(second) == Some("cell") {
            let base = self.ptree(second)?;
            let Some(offset) = reference.value.as_text() else {
                return raise(
                    "TypeError",
                    format!(
                        "expected string or bytes-like object, got '{}'",
                        reference.value.type_name()
                    ),
                );
            };
            let address = abs_addr(&base, &offset)?;
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::str(&address),
                Some(address),
            ));
        }
        let text = self.ptree(root)?;
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(&text),
            Some(text),
        ))
    }

    fn address_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let row = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let col = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let mut optional = true;
        let mut abs_num = Value::Int(1);
        if args.len() >= 3 {
            let evaluated = self.evaluate_parse_tree(cell, &args[2], i)?;
            if evaluated.status == Status::FullEvaluation {
                abs_num = evaluated.value;
            } else {
                optional = false;
            }
        }
        let mut a1 = Value::str("TRUE");
        if args.len() >= 4 {
            let evaluated = self.evaluate_parse_tree(cell, &args[3], i)?;
            if evaluated.status == Status::FullEvaluation {
                a1 = evaluated.value;
            } else {
                optional = false;
            }
        }
        let mut sheet_name = cell.borrow().sheet_name();
        if args.len() >= 5 {
            let evaluated = self.evaluate_parse_tree(cell, &args[4], i)?;
            if evaluated.status == Status::FullEvaluation {
                let Some(text) = &evaluated.text else {
                    return attr_error("NoneType", "strip");
                };
                sheet_name = strip_quotes(text).to_owned();
            } else {
                optional = false;
            }
        }
        if row.status == Status::FullEvaluation && col.status == Status::FullEvaluation && optional
        {
            let abs_number = match &abs_num {
                Value::Int(n) => *n,
                Value::Float(f) if *f == f.trunc() => *f as i128,
                Value::Bool(b) => i128::from(*b),
                _ => 0,
            };
            let row_text = row.text.clone().unwrap_or_else(|| "None".to_owned());
            let col_text = col.text.clone().unwrap_or_else(|| "None".to_owned());
            let body = if a1.is_str("FALSE") {
                match abs_number {
                    2 => format!("R{row_text}C[{col_text}]"),
                    3 => format!("R[{row_text}]C{col_text}"),
                    4 => format!("R[{row_text}]C[{col_text}]"),
                    _ => format!("R{row_text}C{col_text}"),
                }
            } else {
                let column = column_name(col.value.to_int()?);
                match abs_number {
                    2 => format!("{column}${row_text}"),
                    3 => format!("${column}{row_text}"),
                    4 => format!("{column}{row_text}"),
                    _ => format!("${column}${row_text}"),
                }
            };
            let value = format!("{sheet_name}!{body}");
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::str(&value),
                Some(value),
            ));
        }
        // the library's return_val is here an EvalResult, whose str has an address in it
        let shown = "<XLMMacroDeobfuscator.deobfuscator.EvalResult object>";
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::Object(Rc::from(shown)),
            Some(shown.to_owned()),
        ))
    }

    fn indirect_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let address = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if address.status != Status::FullEvaluation {
            let shown = "<XLMMacroDeobfuscator.deobfuscator.EvalResult object>";
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::Object(Rc::from(shown)),
                Some(shown.to_owned()),
            ));
        }
        if args.len() == 2 {
            let _a1 = self.evaluate_parse_tree(cell, &args[1], i)?;
        }
        let (sheet, col, row) = parse_cell_addr_value(&address.value)?;
        let found = self.get_cell(&sheet, &col, row.as_deref().unwrap_or("None"))?;
        let Some(found) = found else {
            return attr_error("NoneType", "value");
        };
        let (value, text) = text_value(found.borrow().value.clone());
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn register_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        if args.len() < 4 {
            let text = self.ptree(root)?;
            return Ok(result(None, Status::Error, Value::Int(0), Some(text)));
        }
        let mut list = Vec::new();
        for argument in &args[..4] {
            let mut evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            list.push(evaluated.get_text(true)?);
        }
        let name = format!("{}.{}", list[0], list[1]);
        self.registered.insert(list[3].clone(), Registered { name });
        let mut listed = self.evaluate_argument_list(cell, "REGISTER", args)?;
        let text = listed.get_text(true)?;
        Ok(result(
            None,
            Status::FullEvaluation,
            Value::Int(0),
            Some(text),
        ))
    }

    fn registerid_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        if args.len() < 3 {
            let text = self.ptree(root)?;
            return Ok(result(None, Status::Error, Value::Int(0), Some(text)));
        }
        let mut list = Vec::new();
        for argument in &args[..3] {
            let mut evaluated = self.evaluate_parse_tree(cell, argument, i)?;
            list.push(evaluated.get_text(true)?);
        }
        let name = format!("{}.{}", list[0], list[1]);
        let mut listed = self.evaluate_argument_list(cell, "REGISTER.ID", args)?;
        let text = listed.get_text(true)?;
        Ok(result(
            None,
            Status::FullEvaluation,
            Value::string(name),
            Some(text),
        ))
    }

    fn return_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut evaluated = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if let Some(return_cell) = self.function_call_stack.pop() {
            return_cell.borrow_mut().value = evaluated.value.clone();
            let (sheet, column, row) = {
                let borrowed = return_cell.borrow();
                (
                    borrowed.sheet.clone(),
                    borrowed.column.clone(),
                    borrowed.row.clone(),
                )
            };
            let next_row = (int_of_row(&row)? + 1).to_string();
            let Some(sheet) = sheet else {
                return attr_error("NoneType", "cells");
            };
            evaluated.next_cell = self.get_formula_cell(&sheet, &column, &Some(next_row))?;
        }
        if evaluated.text.as_deref() == Some("") {
            evaluated.text = Some("RETURN()".to_owned());
        }
        let _ = cell;
        Ok(evaluated)
    }

    fn fopen_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let access = if args.len() > 1 {
            self.evaluate_parse_tree(cell, &args[1], i)?.value
        } else {
            Value::str("1")
        };
        let name = if first.status == Status::FullEvaluation {
            first.get_text(true)?
        } else {
            "default_name".to_owned()
        };
        self.files.entry(name.clone()).or_insert(FileRecord {
            access: access.clone(),
            content: String::new(),
        });
        let text = format!("FOPEN({},{})", first.get_text(false)?, access.to_py_str());
        Ok(result(None, first.status, Value::string(name), Some(text)))
    }

    fn fsize_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let name = first.get_text(true)?;
        let mut status = Status::PartialEvaluation;
        let mut number = 0;
        if let Some(file) = self.files.get(&name) {
            status = Status::FullEvaluation;
            number = file.content.chars().count() as i128;
        }
        wrap_str_literal(&Value::str(&name), false)?;
        let (value, text) = text_value(Value::Int(number));
        Ok(result(None, status, value, text))
    }

    fn fwrite_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        end_line: &str,
    ) -> R<EvalResult> {
        let first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut second = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let Some(mut name) = first.value.as_text() else {
            return attr_error(first.value.type_name(), "strip");
        };
        let as_value = Value::str(&name);
        if name.trim_matches(crate::py::is_space).is_empty()
            || as_value.is_int()?
            || as_value.is_float()
        {
            name = match self.files.keys().next() {
                Some(key) => key.clone(),
                None => "default_filename".to_owned(),
            };
        }
        let content = second.get_text(true)?;
        let mut status = Status::PartialEvaluation;
        if let Some(file) = self.files.get_mut(&name) {
            status = Status::FullEvaluation;
            file.content.push_str(&content);
            file.content.push_str(end_line);
            if file.content.len() > STRING_LIMIT {
                return memory_error();
            }
        }
        let text = format!(
            "FWRITE({},{})",
            wrap_str_literal(&Value::str(&name), false)?,
            wrap_str_literal(&Value::str(&content), false)?
        );
        Ok(result(None, status, Value::str("0"), Some(text)))
    }

    fn files_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let name = first.get_text(true)?;
        let text = format!("FILES({})", wrap_str_literal(&Value::str(&name), false)?);
        Ok(result(
            None,
            Status::FullEvaluation,
            Value::string(name),
            Some(text),
        ))
    }

    fn iserror_handler(&mut self, args: &Args, cell: &CellRef, i: bool) -> R<EvalResult> {
        let mut first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut value = matches!(first.value, Value::None);
        match &self.iserror_loc {
            None => {
                self.iserror_val = value;
                self.iserror_loc = Some(cell.clone());
                self.iserror_count = 1;
            }
            Some(place) if Rc::ptr_eq(place, cell) => {
                if self.iserror_val != value {
                    self.iserror_val = value;
                    self.iserror_count = 1;
                } else if self.iserror_count < MAX_ISERROR_LOOPCOUNT {
                    self.iserror_count += 1;
                } else {
                    value = !value;
                    self.iserror_loc = None;
                }
            }
            Some(_) => {}
        }
        let text = format!(
            "ISERROR({})",
            wrap_str_literal(&Value::string(first.get_text(true)?), false)?
        );
        Ok(result(
            None,
            Status::FullEvaluation,
            Value::Bool(value),
            Some(text),
        ))
    }

    fn offset_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let (sheet, col, row) = self.get_cell_addr(cell, arg(args, 0)?)?;
        let row_index = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let col_index = self.evaluate_parse_tree(cell, arg(args, 2)?, i)?;
        let mut value = Value::Int(0);
        let mut next = None;
        let mut status = Status::PartialEvaluation;
        if row_index.status == Status::FullEvaluation && col_index.status == Status::FullEvaluation
        {
            let new_row = int_of_row(&row)?
                + float_to_int(Value::string(row_index.value.to_py_str()).to_float()?)?;
            let new_col = column_name(
                index_of_col(&col)?
                    + float_to_int(Value::string(col_index.value.to_py_str()).to_float()?)?,
            );
            let row_text = new_row.to_string();
            value = Value::Tuple(Rc::new(vec![
                sheet.as_ref().map_or(Value::None, |s| Value::str(s)),
                Value::str(&new_col),
                Value::str(&row_text),
            ]));
            status = Status::FullEvaluation;
            let sheets = self.macrosheets()?;
            let Some(found) = sheet.as_ref().and_then(|name| sheets.get(name)) else {
                return raise(
                    "KeyError",
                    sheet
                        .as_ref()
                        .map_or("None".to_owned(), |name| repr_str(name)),
                );
            };
            next = self.get_formula_cell(found, &Some(new_col), &Some(row_text))?;
        }
        let text = self.ptree(root)?;
        Ok(result(next, status, value, Some(text)))
    }

    fn arabic_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let mut first = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        if first.status != Status::FullEvaluation {
            let _ = root;
            return unbound("status");
        }
        let numeral = first.get_text(true)?;
        let number = from_roman(&numeral)?;
        let (value, text) = text_value(Value::Int(number));
        Ok(result(None, Status::FullEvaluation, value, text))
    }

    fn virtual_alloc_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let mut base_arg = self.evaluate_parse_tree(cell, arg(args, 0)?, i)?;
        let mut size_arg = self.evaluate_parse_tree(cell, arg(args, 1)?, i)?;
        let mut value = Value::Int(0);
        let mut status = Status::PartialEvaluation;
        if base_arg.status == Status::FullEvaluation && size_arg.status == Status::FullEvaluation {
            let base = Value::string(base_arg.get_text(true)?).to_int()?;
            for record in &self.memory {
                if record.base <= base && base <= record.base + record.size {
                    return raise(
                        "TypeError",
                        "unsupported operand type(s) for +: 'map' and 'int'",
                    );
                }
            }
            let size = Value::string(size_arg.get_text(true)?).to_int()?;
            let held: i128 = self.memory.iter().map(|record| record.size.max(0)).sum();
            if size.saturating_add(held) > MEMORY_LIMIT {
                return memory_error();
            }
            self.memory.push(MemoryRecord {
                base,
                size,
                data: vec![0; size.max(0) as usize],
            });
            value = Value::Int(base);
            status = Status::FullEvaluation;
        }
        let text = self.ptree(root)?;
        Ok(result(None, status, value, Some(text)))
    }

    fn write_memory(&mut self, base: i128, data: &[u8], size: i128) -> R<bool> {
        for record in &mut self.memory {
            if record.base <= base && base <= record.base + record.size {
                if record.base <= base + size && base + size <= record.base + record.size {
                    let offset = base - record.base;
                    for index in 0..size.max(0) {
                        let Some(byte) = data.get(index as usize) else {
                            return raise("IndexError", "bytearray index out of range");
                        };
                        let Some(place) = record.data.get_mut((offset + index) as usize) else {
                            return raise("IndexError", "list assignment index out of range");
                        };
                        *place = *byte;
                    }
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn write_process_memory_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        if args.len() <= 4 {
            // the library falls off the end of the handler, and its caller then sets an attribute on None
            return raise(
                "AttributeError",
                "'NoneType' object has no attribute 'output_level' and no __dict__ for setting new attributes",
            );
        }
        let mut status = Status::FullEvaluation;
        let mut evaluated = Vec::new();
        for argument in args {
            let one = self.evaluate_parse_tree(cell, argument, i)?;
            if one.status != Status::FullEvaluation {
                status = one.status;
            }
            evaluated.push(one);
        }
        let mut text = None;
        if status == Status::FullEvaluation {
            let base = evaluated[1].value.to_int()?;
            let data = bytes_of(&evaluated[2].value)?;
            let size = evaluated[3].value.to_int()?;
            if !self.write_memory(base, &data, size)? {
                status = Status::Error;
            }
            let first = evaluated[0].get_text(false)?;
            let last = evaluated[4].get_text(false)?;
            text = Some(format!(
                "Kernel32.WriteProcessMemory({first},{base},\"{}\",{size},{last})",
                hex(&data)
            ));
        }
        if status != Status::FullEvaluation {
            text = Some(self.ptree(root)?);
        }
        Ok(result(None, status, Value::Int(0), text))
    }

    fn rtl_copy_memory_handler(
        &mut self,
        args: &Args,
        cell: &CellRef,
        i: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let mut status = Status::PartialEvaluation;
        let mut text = None;
        if args.len() == 3 {
            let mut destination = self.evaluate_parse_tree(cell, &args[0], i)?;
            let source = self.evaluate_parse_tree(cell, &args[1], i)?;
            let mut size = self.evaluate_parse_tree(cell, &args[2], i)?;
            if destination.status == Status::FullEvaluation
                && source.status == Status::FullEvaluation
            {
                status = Status::FullEvaluation;
                let data = bytes_of(&source.value)?;
                let length = data.len() as i128;
                if !self.write_memory(destination.value.to_int()?, &data, length)? {
                    status = Status::Error;
                }
                text = Some(format!(
                    "Kernel32.RtlCopyMemory({},\"{}\",{})",
                    destination.get_text(false)?,
                    hex(&data),
                    size.get_text(false)?
                ));
            }
        }
        if status == Status::PartialEvaluation {
            text = Some(self.ptree(root)?);
        }
        Ok(result(None, status, Value::Int(0), text))
    }

    fn evaluate_defined_name(
        &mut self,
        current: &CellRef,
        name: &str,
        interactive: bool,
    ) -> R<Value> {
        let lower = py_lower(name);
        let held = self.defined_names.borrow().get(&lower).cloned();
        let Some(held) = held else {
            return Ok(Value::None);
        };
        match &held {
            Value::Node(node) if data_of(node) == Some("cell") => {
                let evaluated = self.evaluate_cell(current, interactive, node)?;
                Ok(evaluated.value)
            }
            Value::List(_) => Ok(held),
            _ => {
                let data = match &held {
                    Value::Cell(found) => found.borrow().value.clone(),
                    other => other.clone(),
                };
                let text = data.to_py_str();
                let formula = if text.starts_with('=') {
                    text.clone()
                } else {
                    format!("={text}")
                };
                // a bare `except:`, which a pass's clock isn't for
                let attempt = (|| -> R<Value> {
                    let parsed = self.parse(&formula)?;
                    let evaluated = self.evaluate_parse_tree(current, &parsed, interactive)?;
                    Ok(match evaluated.value {
                        Value::List(items) => Value::List(items),
                        other => Value::string(other.to_py_str()),
                    })
                })();
                match attempt {
                    Ok(value) => Ok(value),
                    Err(Raised::Exception { .. }) => Ok(Value::string(text)),
                    Err(other) => Err(other),
                }
            }
        }
    }

    pub fn evaluate_parse_tree(
        &mut self,
        current: &CellRef,
        root: &Node,
        interactive: bool,
    ) -> R<EvalResult> {
        self.frame(1, |this| {
            this.evaluate_parse_tree_inner(current, root, interactive)
        })
    }

    fn evaluate_parse_tree_inner(
        &mut self,
        current: &CellRef,
        root: &Node,
        interactive: bool,
    ) -> R<EvalResult> {
        self.tick()?;
        let tree = match root {
            Node::Token(token) => {
                let value = token.value.borrow().clone();
                let Some(text) = value.as_text() else {
                    return attr_error(value.type_name(), "lower");
                };
                if self.defined_names.borrow().contains_key(&py_lower(&text)) {
                    self.remove_current_formula = true;
                    let evaluated = self.frame(1, |this| {
                        this.evaluate_defined_name(current, &text, interactive)
                    })?;
                    *token.value.borrow_mut() = evaluated;
                }
                let value = token.value.borrow().clone();
                let (value, text) = text_value(value);
                return Ok(result(None, Status::FullEvaluation, value, text));
            }
            Node::EmptyList => {
                return Ok(result(
                    None,
                    Status::FullEvaluation,
                    Value::str(""),
                    Some(String::new()),
                ));
            }
            Node::Tree(tree) => tree,
        };
        match tree.data {
            "function_call" => {
                self.frame(1, |this| this.evaluate_function(current, tree, interactive))
            }
            "cell" => self.evaluate_cell(current, interactive, root),
            "range" => self.frame(1, |this| this.evaluate_range(current, tree)),
            "array" => evaluate_array(tree),
            "expression"
            | "concat_expression"
            | "additive_expression"
            | "multiplicative_expression" => self.evaluate_expression(current, tree, interactive),
            "final" => {
                let inner = child(tree, 1)?;
                self.evaluate_parse_tree(current, &inner, interactive)
            }
            _ => {
                let mut status = Status::FullEvaluation;
                let children = tree.children.borrow().clone();
                let mut last = None;
                for node in &children {
                    let evaluated = self.evaluate_parse_tree(current, node, interactive)?;
                    if evaluated.status != Status::FullEvaluation {
                        status = evaluated.status;
                    }
                    last = Some(evaluated);
                }
                let Some(last) = last else {
                    return unbound("child_eval_result");
                };
                let mut answer = result(last.next_cell, status, last.value, last.text);
                answer.output_level = last.output_level;
                Ok(answer)
            }
        }
    }

    fn evaluate_expression(
        &mut self,
        current: &CellRef,
        tree: &Rc<Tree>,
        interactive: bool,
    ) -> R<EvalResult> {
        let children = tree.children.borrow().clone();
        let mut text_left: Option<Value> = None;
        let mut value_left = Value::None;
        let mut left_status: Option<Status> = None;
        let mut concat_status = Status::FullEvaluation;
        let mut return_val = Value::None;
        for (index, node) in children.iter().enumerate() {
            let op = match node {
                Node::Token(token)
                    if matches!(
                        token.kind_name(),
                        "ADDITIVEOP" | "MULTIOP" | "CMPOP" | "CONCATOP"
                    ) =>
                {
                    Some(token.text.clone())
                }
                _ => None,
            };
            if let Some(op) = op {
                let right_node = children.get(index + 1).map_or_else(index_error, Ok)?;
                let mut right = self.evaluate_parse_tree(current, right_node, interactive)?;
                let mut text_right = match &right.value {
                    Value::Cell(found) => {
                        let inner = found.borrow().value.clone();
                        unwrap_str_literal(&inner.to_py_str())
                    }
                    _ => right.get_text(true)?,
                };
                let Some(status_left) = left_status else {
                    return unbound("left_arg_eval_res");
                };
                let right_full = right.status == Status::FullEvaluation;
                let left_full = status_left == Status::FullEvaluation;
                let held_left = text_left.clone().unwrap_or(Value::None).to_py_str();
                if op == "&" {
                    if left_full && !right_full {
                        text_left = Some(Value::string(format!("{held_left}&{text_right}")));
                        left_status = Some(Status::PartialEvaluation);
                        concat_status = Status::PartialEvaluation;
                    } else if !left_full && right_full {
                        text_left = Some(Value::string(format!("{held_left}&{text_right}")));
                        left_status = Some(Status::FullEvaluation);
                        concat_status = Status::PartialEvaluation;
                    } else if !left_full && !right_full {
                        text_left = Some(Value::string(format!("{held_left}&{text_right}")));
                        left_status = Some(Status::PartialEvaluation);
                        concat_status = Status::PartialEvaluation;
                    } else {
                        // str + str, which a bool on the left can't do
                        if let Some(held) = &text_left
                            && held.as_text().is_none()
                        {
                            return raise(
                                "TypeError",
                                format!(
                                    "unsupported operand type(s) for +: '{}' and 'str'",
                                    held.type_name()
                                ),
                            );
                        }
                        let mut joined = String::with_capacity(held_left.len() + text_right.len());
                        joined.push_str(&held_left);
                        joined.push_str(&text_right);
                        check_size(&joined)?;
                        text_left = Some(Value::string(joined));
                    }
                } else if left_full && right_full {
                    let mut value_right = match &right.value {
                        Value::Cell(found) => found.borrow().value.clone(),
                        other => {
                            let mut held = other.clone();
                            if let Value::Str(text) = &held {
                                let lower = py_lower(text);
                                if lower == "true" {
                                    held = Value::Int(1);
                                } else if lower == "false" {
                                    held = Value::Int(0);
                                }
                            }
                            held
                        }
                    };
                    let mut left_text = held_left;
                    if left_text.is_empty() {
                        left_text = "0".to_owned();
                        value_left = Value::Int(0);
                    }
                    if text_right.is_empty() {
                        text_right = "0".to_owned();
                        value_right = Value::Int(0);
                    }
                    if value_left.is_float() && value_right.is_float() {
                        let (a, b) = (value_left.to_float()?, value_right.to_float()?);
                        value_left = match float_operator(&op, a, b)? {
                            FloatOp::Truth(truth) => Value::string(Value::Bool(truth).to_py_str()),
                            FloatOp::Number(number) => {
                                if number.is_finite() && number == number.trunc() {
                                    Value::string(integer_float_str(number))
                                } else {
                                    Value::string(super::value::float_str(py_round(number, 10)))
                                }
                            }
                        };
                    } else if let (Some(a), Some(b)) = (
                        parse_datetime(strip_quotes(&left_text)),
                        parse_datetime(strip_quotes(&text_right)),
                    ) {
                        let shown = match float_operator(&op, a, b)? {
                            FloatOp::Truth(truth) => (i128::from(truth) + 1000).to_string(),
                            FloatOp::Number(number) => {
                                let number = number + 1000.0;
                                if number.is_finite() && number == number.trunc() {
                                    super::value::float_str(number)
                                } else {
                                    super::value::float_str(py_round(number, 10))
                                }
                            }
                        };
                        value_left = Value::string(shown);
                    } else if let (Some(a), Some(b)) = (
                        parse_datetime(strip_quotes(&left_text)),
                        parse_time(strip_quotes(&text_right)),
                    ) {
                        let number = match float_operator(&op, a, b as f64)? {
                            FloatOp::Truth(truth) => f64::from(u8::from(truth)),
                            FloatOp::Number(number) => number,
                        };
                        value_left = Value::string(datetime_str(number));
                    } else {
                        let left = unwrap_str_literal(&value_left.to_py_str());
                        let right_text = unwrap_str_literal(&value_right.to_py_str());
                        value_left = str_operator(&op, &left, &right_text)?;
                    }
                    text_left = Some(value_left.clone());
                } else {
                    left_status = Some(Status::PartialEvaluation);
                    text_left = Some(Value::string(format!("{held_left}{op}{text_right}")));
                }
                return_val = text_left.clone().unwrap_or(Value::None);
            } else if text_left.is_none() {
                let mut left = self.evaluate_parse_tree(current, node, interactive)?;
                text_left = Some(Value::string(left.get_text(true)?));
                value_left = match &left.value {
                    Value::Cell(found) => found.borrow().value.clone(),
                    other => {
                        let mut held = other.clone();
                        if let Value::Str(text) = &held {
                            let lower = py_lower(text);
                            if lower == "true" {
                                held = Value::Int(1);
                            } else if lower == "false" {
                                held = Value::Int(0);
                            }
                        }
                        held
                    }
                };
                left_status = Some(left.status);
            }
        }
        let Some(mut status) = left_status else {
            return unbound("left_arg_eval_res");
        };
        if concat_status == Status::PartialEvaluation && status == Status::FullEvaluation {
            status = concat_status;
        }
        let shown = wrap_str_literal(&text_left.unwrap_or(Value::None), false)?;
        Ok(result(None, status, return_val, Some(shown)))
    }

    fn evaluate_cell(
        &mut self,
        current: &CellRef,
        interactive: bool,
        root: &Node,
    ) -> R<EvalResult> {
        self.frame(1, |this| {
            this.evaluate_cell_inner(current, interactive, root)
        })
    }

    fn evaluate_cell_inner(
        &mut self,
        current: &CellRef,
        interactive: bool,
        root: &Node,
    ) -> R<EvalResult> {
        let (sheet_name, col, row) = self.get_cell_addr(current, root)?;
        let Some(sheet_name) = sheet_name else {
            let text = self.ptree(root)?;
            return Ok(result(
                None,
                Status::PartialEvaluation,
                Value::str(""),
                Some(text),
            ));
        };
        let address = concat_address(&col, row.as_deref().unwrap_or("None"))?;
        let macrosheets = self.macrosheets()?;
        let sheet = match macrosheets.get(&sheet_name) {
            Some(sheet) => sheet.clone(),
            None => match self.wrapper.get_worksheets()?.get(&sheet_name) {
                Some(sheet) => sheet.clone(),
                None => return raise("KeyError", repr_str(&sheet_name)),
            },
        };
        let unknown = (Some(sheet_name.clone()), address.clone());
        let found = sheet.cell(&address);
        let in_unsuccessful = self.unsuccessful.contains(&unknown);
        if found.is_none() && in_unsuccessful && interactive {
            self.invoke_interpreter = true;
            if self.first_unknown_cell.is_none() {
                self.first_unknown_cell = Some(address.clone());
            }
        }
        let Some(found) = found else {
            return Ok(if in_unsuccessful {
                result(
                    None,
                    Status::PartialEvaluation,
                    Value::str(""),
                    Some(address),
                )
            } else {
                result(
                    None,
                    Status::FullEvaluation,
                    Value::str(""),
                    Some(String::new()),
                )
            });
        };
        let (formula, value) = {
            let borrowed = found.borrow();
            (borrowed.formula.clone(), borrowed.value.clone())
        };
        if let Some(formula) = formula.filter(|f| !value.is_str(f)) {
            // a bare `except:`: the formula's own text stands for the cell
            let attempt = (|| -> R<EvalResult> {
                let parsed = self.parse(&formula)?;
                let mut evaluated = self.evaluate_parse_tree(&found, &parsed, false)?;
                let text = evaluated.get_text(false)?;
                Ok(result(None, evaluated.status, evaluated.value, Some(text)))
            })();
            return match attempt {
                Ok(answer) => Ok(answer),
                Err(Raised::Exception { .. }) => {
                    let text = wrap_str_literal(&Value::str(&formula), false)?;
                    Ok(result(
                        None,
                        Status::FullEvaluation,
                        Value::string(formula),
                        Some(text),
                    ))
                }
                Err(other) => Err(other),
            };
        }
        if !matches!(value, Value::None) {
            let text = wrap_str_literal(&value, true)?;
            return Ok(result(
                None,
                Status::FullEvaluation,
                Value::str(&text),
                Some(text),
            ));
        }
        Ok(result(
            None,
            Status::PartialEvaluation,
            Value::str(""),
            Some(address),
        ))
    }

    fn evaluate_range(&mut self, current: &CellRef, tree: &Rc<Tree>) -> R<EvalResult> {
        let children = tree.children.borrow().clone();
        let mut status = Status::PartialEvaluation;
        if children.len() >= 3 {
            let start = self.get_cell_addr(current, &children[0])?;
            let end = self.get_cell_addr(current, &children[2])?;
            let selected = if children.len() == 5 {
                Some(self.get_cell_addr(current, &children[4])?)
            } else {
                None
            };
            self.selected_range = Some((start, end, selected));
            status = Status::FullEvaluation;
        }
        let text = self.ptree(&Node::Tree(tree.clone()))?;
        Ok(result(None, status, Value::str(&text), Some(text)))
    }

    /// `has_loop`, over the cells seen so far.
    fn has_loop(path: &[String], length: usize) -> bool {
        if path.len() < length * 2 {
            return false;
        }
        let start_index = path.len() - length;
        for j in 0..start_index.saturating_sub(length) {
            let mut matched = true;
            let mut k = j;
            while start_index + k - j < path.len() {
                if path[k] != path[start_index + k - j] {
                    matched = false;
                    break;
                }
                k += 1;
            }
            if matched {
                return true;
            }
        }
        false
    }

    fn interactive_shell(&self, current: &CellRef, message: &str) -> R<()> {
        let (address, formula) = {
            let borrowed = current.borrow();
            (borrowed.local_address()?, borrowed.formula.clone())
        };
        self.print("\nProcess Interruption:")?;
        self.print(&format!(
            "CELL:{address:<10}{}",
            formula.as_deref().unwrap_or("None")
        ))?;
        self.print(message)?;
        self.print("Enter XLM macro:")?;
        self.print("Tip: CLOSE() or HALT() to exist")?;
        // stdin is at its end, in ace3 and here
        raise("EOFError", "EOF when reading a line")
    }

    fn report_error(&self, line: u32, source: &str, message: &str, silent: bool) -> R<()> {
        if silent {
            return Ok(());
        }
        self.print(&format!(
            "Error [deobfuscator.py:{line} {source}]: {message}"
        ))
    }

    /// `deobfuscate_macro`, with its yields as calls to `on_step`, which says whether to go on.
    pub fn deobfuscate_macro(
        &mut self,
        interactive: bool,
        silent: bool,
        on_step: &mut dyn FnMut(Step) -> R<()>,
    ) -> R<()> {
        let mut labels = list_items(&self.wrapper.get_defined_name("auto_open", false)?);
        labels.extend(list_items(
            &self.wrapper.get_defined_name("auto_close", false)?,
        ));
        self.auto_labels = labels;
        if self.auto_labels.is_empty() && interactive {
            self.print("There is no entry point, please specify a cell address to start")?;
            self.print("Example: Sheet1!A1")?;
            return raise("EOFError", "EOF when reading a line");
        }
        if self.auto_labels.is_empty() {
            return Ok(());
        }
        let macros = self.macrosheets()?;
        for label in self.auto_labels.clone() {
            match self.run_label(&label, &macros, interactive, on_step) {
                Ok(()) => {}
                Err(Located::Raised(line, source, Raised::Exception { message, .. })) => {
                    self.report_error(line, source, &message, silent)?;
                }
                Err(Located::Raised(_, _, other)) => return Err(other),
            }
        }
        Ok(())
    }

    /// One entry point.
    fn run_label(
        &mut self,
        label: &Value,
        macros: &IndexMap<String, SheetRef>,
        interactive: bool,
        on_step: &mut dyn FnMut(Step) -> R<()>,
    ) -> Result<(), Located> {
        const LINE_ADDR: (u32, &str) = (
            2566,
            "sheet_name, col, row = Cell.parse_cell_addr(auto_open_label[1])",
        );
        const LINE_START: (u32, &str) = (
            2568,
            "current_cell = self.get_formula_cell(macros[sheet_name], col, row)",
        );
        const LINE_STACK: (u32, &str) = (
            2569,
            "self._branch_stack = [(current_cell, current_cell.formula, macros[sheet_name].cells, 0, '')]",
        );
        const LINE_POP: (u32, &str) = (2575, "macros[current_cell.sheet.name].cells = saved_cells");
        const LINE_PARSE: (u32, &str) = (2586, "parse_tree = self.xlm_parser.parse(formula)");
        const LINE_EVAL: (u32, &str) = (
            2598,
            "evaluation_result = self.evaluate_parse_tree(current_cell, parse_tree, interactive)",
        );
        const LINE_ADDRESS: (u32, &str) = (
            2606,
            "observed_cells.append(current_cell.get_local_address())",
        );
        const LINE_SHELL: (u32, &str) = (2612, "self.interactive_shell(");
        const LINE_NEXT: (u32, &str) = (
            2628,
            "evaluation_result.next_cell = self.get_formula_cell(current_cell.sheet,",
        );
        const LINE_NEXT_ROW: (u32, &str) = (2630, "str(int(current_cell.row) + 1))");
        const LINE_TEXT: (u32, &str) = (
            2633,
            "desc + ' ' + evaluation_result.get_text(unwrap=False)).strip()",
        );
        const LINE_OUT: (u32, &str) = (2650, "evaluation_result.get_text(unwrap=False),");

        let at = |line: (u32, &'static str)| {
            move |raised: Raised| Located::Raised(line.0, line.1, raised)
        };
        let Value::Tuple(parts) = label else {
            return Err(at(LINE_ADDR)(Raised::Exception {
                kind: "IndexError",
                message: "list index out of range".to_owned(),
            }));
        };
        let address = parts.get(1).cloned().unwrap_or(Value::None);
        let (sheet_name, col, row) = parse_cell_addr_value(&address).map_err(at(LINE_ADDR))?;
        let Some(sheet) = sheet_name
            .as_ref()
            .and_then(|name| macros.get(name))
            .cloned()
        else {
            return Ok(());
        };
        let start = self
            .get_formula_cell(&sheet, &col, &row)
            .map_err(at(LINE_START))?;
        let Some(start) = start else {
            return Err(at(LINE_STACK)(Raised::Exception {
                kind: "AttributeError",
                message: "'NoneType' object has no attribute 'formula'".to_owned(),
            }));
        };
        let start_formula = start.borrow().formula.clone();
        self.branch_stack = vec![Frame {
            cell: start,
            formula: Formula::Text(start_formula),
            cells: sheet.cells.borrow().clone(),
            indent: 0,
            desc: "",
        }];
        let mut observed: Vec<String> = Vec::new();
        while let Some(frame) = self.branch_stack.pop() {
            let Frame {
                cell: mut current,
                mut formula,
                cells,
                indent,
                desc,
            } = frame;
            let current_sheet = current.borrow().sheet.clone();
            let current_name = current_sheet
                .as_ref()
                .map_or(String::new(), |s| s.name.clone());
            let Some(target) = macros.get(&current_name) else {
                return Err(at(LINE_POP)(Raised::Exception {
                    kind: "KeyError",
                    message: repr_str(&current_name),
                }));
            };
            *target.cells.borrow_mut() = cells;
            self.indent_level = indent;
            let mut stack_record = true;
            loop {
                self.tick().map_err(at(LINE_EVAL))?;
                let parse_tree = match &formula {
                    Formula::Tree(node) => node.clone(),
                    Formula::Text(None) => {
                        // a cell whose formula went: `formula` is None and it's evaluated as a tree
                        return Err(at(LINE_EVAL)(Raised::Exception {
                            kind: "AttributeError",
                            message: "'NoneType' object has no attribute 'data'".to_owned(),
                        }));
                    }
                    Formula::Text(Some(text)) => {
                        let text = if self.wrapper.replaces_nonprintable() {
                            replace_nonprintable(text)
                        } else {
                            text.clone()
                        };
                        let cached = self.formula_cache.borrow().get(&text).cloned();
                        let node = match cached {
                            Some(node) => node,
                            None => {
                                let node = self.parse(&text).map_err(at(LINE_PARSE))?;
                                self.store(text.len()).map_err(at(LINE_PARSE))?;
                                self.formula_cache
                                    .borrow_mut()
                                    .insert(text.clone(), node.clone());
                                node
                            }
                        };
                        formula = Formula::Text(Some(text));
                        node
                    }
                };
                let previous_indent = if stack_record && self.indent_level > 0 {
                    self.indent_level - 1
                } else if stack_record {
                    0
                } else {
                    self.indent_level
                };
                let mut previous_indent = previous_indent;
                let mut evaluated = self
                    .evaluate_parse_tree(&current, &parse_tree, interactive)
                    .map_err(at(LINE_EVAL))?;
                if self.remove_current_formula {
                    self.remove_current_formula = false;
                    if let Formula::Text(Some(text)) = &formula {
                        self.formula_cache.borrow_mut().remove(text);
                    }
                }
                if self.while_stack.is_empty() && evaluated.text.as_deref() != Some("NEXT") {
                    let address = current.borrow().local_address().map_err(at(LINE_ADDRESS))?;
                    observed.push(address);
                    if Self::has_loop(&observed, 10) {
                        break;
                    }
                }
                if self.invoke_interpreter && interactive {
                    let message = format!(
                        "Partial Eval: {}\r\n{} is not populated, what should be its value?",
                        evaluated.text.as_deref().unwrap_or("None"),
                        self.first_unknown_cell.as_deref().unwrap_or("None")
                    );
                    self.interactive_shell(&current, &message)
                        .map_err(at(LINE_SHELL))?;
                }
                if !matches!(evaluated.value, Value::None) {
                    let text = evaluated.value.to_py_str();
                    self.store(text.len()).map_err(at(LINE_EVAL))?;
                    current.borrow_mut().value = Value::string(text);
                }
                if evaluated.next_cell.is_none()
                    && matches!(
                        evaluated.status,
                        Status::FullEvaluation | Status::PartialEvaluation | Status::Ignored
                    )
                {
                    let (sheet, column, row) = {
                        let borrowed = current.borrow();
                        (
                            borrowed.sheet.clone(),
                            borrowed.column.clone(),
                            borrowed.row.clone(),
                        )
                    };
                    let next_row = int_of_row(&row).map_err(at(LINE_NEXT_ROW))? + 1;
                    let Some(sheet) = sheet else {
                        return Err(at(LINE_NEXT)(Raised::Exception {
                            kind: "AttributeError",
                            message: "'NoneType' object has no attribute 'cells'".to_owned(),
                        }));
                    };
                    evaluated.next_cell = self
                        .get_formula_cell(&sheet, &column, &Some(next_row.to_string()))
                        .map_err(at(LINE_NEXT))?;
                }
                if stack_record {
                    let text = evaluated.get_text(false).map_err(at(LINE_TEXT))?;
                    let joined = format!("{desc} {text}");
                    evaluated.text = Some(joined.trim_matches(crate::py::is_space).to_owned());
                }
                if self.indent_current_line {
                    previous_indent = self.indent_level;
                    self.indent_current_line = false;
                }
                if evaluated.status != Status::Ignored {
                    let text = evaluated.get_text(false).map_err(at(LINE_OUT))?;
                    on_step(Step {
                        cell: current.clone(),
                        status: evaluated.status,
                        text,
                        indent: previous_indent,
                    })
                    .map_err(at(LINE_OUT))?;
                }
                let Some(next) = evaluated.next_cell else {
                    break;
                };
                current = next;
                let next_formula = current.borrow().formula.clone();
                formula = Formula::Text(next_formula);
                stack_record = false;
            }
        }
        Ok(())
    }
}

pub enum Located {
    Raised(u32, &'static str, Raised),
}

fn evaluate_array(tree: &Rc<Tree>) -> R<EvalResult> {
    let mut elements = Vec::new();
    for (index, node) in tree.children.borrow().iter().enumerate() {
        if index % 2 == 1 {
            continue;
        }
        let Node::Token(token) = node else {
            return attr_error("Tree", "type");
        };
        if token.kind_name() == "NUMBER" {
            elements.push(Value::Float(Value::str(&token.text).to_float()?));
        } else {
            elements.push(Value::str(&token.text));
        }
    }
    let value = Value::List(Rc::new(elements));
    let text = value.repr();
    Ok(result(None, Status::PartialEvaluation, value, Some(text)))
}

fn list_items(value: &Value) -> Vec<Value> {
    match value {
        Value::List(items) => items.to_vec(),
        _ => Vec::new(),
    }
}

fn py_slice(text: &str, from: i128, to: i128) -> String {
    let chars: Vec<char> = text.chars().collect();
    let length = chars.len() as i128;
    let clamp = |at: i128| {
        if at < 0 {
            (at + length).max(0)
        } else {
            at.min(length)
        }
    };
    let (from, to) = (clamp(from), clamp(to));
    if from >= to {
        return String::new();
    }
    chars[from as usize..to as usize].iter().collect()
}

fn bytes_of(value: &Value) -> R<Vec<u8>> {
    let Some(text) = value.as_text() else {
        return raise(
            "TypeError",
            format!("'{}' object is not iterable", value.type_name()),
        );
    };
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        let Ok(byte) = u8::try_from(u32::from(c)) else {
            return raise("ValueError", "byte must be in range(0, 256)");
        };
        out.push(byte);
    }
    Ok(out)
}

fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `roman.fromRoman`.
fn from_roman(text: &str) -> R<i128> {
    const MAP: &[(&str, i128)] = &[
        ("M", 1000),
        ("CM", 900),
        ("D", 500),
        ("CD", 400),
        ("C", 100),
        ("XC", 90),
        ("L", 50),
        ("XL", 40),
        ("X", 10),
        ("IX", 9),
        ("V", 5),
        ("IV", 4),
        ("I", 1),
    ];
    if text.is_empty() {
        return raise("InvalidRomanNumeralError", "Input cannot be blank");
    }
    let upper = text.to_uppercase();
    if upper == "N" {
        return Ok(0);
    }
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        regex::Regex::new(r"^M{0,4}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})\n?$")
            .expect("a valid expression")
    });
    if !pattern.is_match(&upper) {
        return raise(
            "InvalidRomanNumeralError",
            format!("Invalid Roman numeral: {upper}"),
        );
    }
    let mut total = 0;
    let mut index = 0;
    for (numeral, number) in MAP {
        while upper[index..].starts_with(numeral) {
            total += number;
            index += numeral.len();
        }
    }
    Ok(total)
}

/// `replace_nonprintable_chars(formula, '_')`.
fn replace_nonprintable(text: &str) -> String {
    text.chars()
        .map(|c| {
            let code = u32::from(c);
            if code < 32
                || (127..160).contains(&code)
                || matches!(
                    code,
                    0xFEFE
                        | 0xFFFF
                        | 0xFEFF
                        | 0xFFFE
                        | 0xFFEF
                        | 0xFFF0
                        | 0xFFF1
                        | 0xFFF6
                        | 0xFEFD
                        | 0xDDDD
                        | 0xFFFD
                )
            {
                '_'
            } else {
                c
            }
        })
        .collect()
}
