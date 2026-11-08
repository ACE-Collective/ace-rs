//! Hunt files as PyYAML's `yaml.safe_load` reads them (YAML 1.1), within bounds.
//!
//! yaml-rust2 parses; this module builds the values from its events as PyYAML's SafeLoader
//! composes and constructs them: a plain scalar resolves by the YAML 1.1 rules in PyYAML's
//! `resolver.py` (`yes` and `on` are true, `1:30` is 90, `010` is 8, `2024-01-02` is a date), a
//! quoted one is a string, `<<` merges mappings, a later duplicate key replaces the earlier one
//! where it stood, and a stream holds at most one document.
//!
//! Hunt files are trusted signature content but are parsed as untrusted. What the loader builds is
//! bounded by a [`Budget`] that every file of one hunt shares: nodes and bytes of text, counting an
//! alias as a copy of what it names (so an alias bomb runs out of budget instead of memory), and
//! nesting depth. A recursive alias is refused. ace3 has none of these bounds.

use std::sync::LazyLock;

use regex::Regex;
use yaml_rust2::parser::{Event, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

use crate::value::{Map, Value};

/// Bounds on what loading one hunt may build, across all the files it includes.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The largest file read, in bytes. The largest hunt in the signatures is 86 KB.
    pub max_file_bytes: u64,
    /// The most nodes built, aliases counted as copies. The largest hunt has about 600.
    pub max_nodes: usize,
    /// The most bytes of text built, aliases counted as copies.
    pub max_text_bytes: usize,
    /// The deepest nesting of collections. The deepest hunt nests 13.
    pub max_depth: usize,
    /// The most files read for one hunt, includes and their includes.
    pub max_files: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_file_bytes: 1 << 20,
            max_nodes: 100_000,
            max_text_bytes: 16 << 20,
            max_depth: 64,
            max_files: 256,
        }
    }
}

/// What one hunt has used of its [`Limits`].
#[derive(Debug)]
pub struct Budget {
    pub limits: Limits,
    nodes: usize,
    text: usize,
    pub files: usize,
}

impl Budget {
    pub fn new(limits: Limits) -> Budget {
        Budget {
            limits,
            nodes: 0,
            text: 0,
            files: 0,
        }
    }

    fn spend(&mut self, nodes: usize, text: usize) -> Result<(), YamlError> {
        self.nodes += nodes;
        self.text += text;
        if self.nodes > self.limits.max_nodes {
            return Err(YamlError::limit(format!(
                "more than {} YAML nodes, aliases counted as copies",
                self.limits.max_nodes
            )));
        }
        if self.text > self.limits.max_text_bytes {
            return Err(YamlError::limit(format!(
                "more than {} bytes of YAML text, aliases counted as copies",
                self.limits.max_text_bytes
            )));
        }
        Ok(())
    }
}

/// Why a file didn't load: the class of the error PyYAML raises, or `None` for one of ace4's
/// bounds, which PyYAML doesn't have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    pub class: Option<&'static str>,
    pub message: String,
}

impl YamlError {
    fn new(class: &'static str, message: impl Into<String>) -> YamlError {
        YamlError {
            class: Some(class),
            message: message.into(),
        }
    }

    fn limit(message: String) -> YamlError {
        YamlError {
            class: None,
            message,
        }
    }

    /// An error at a place in a file, written as PyYAML writes its marks.
    fn at(class: &'static str, message: impl Into<String>, mark: Marker, name: &str) -> YamlError {
        YamlError::new(
            class,
            format!(
                "{}\n  in \"{name}\", line {}, column {}",
                message.into(),
                mark.line(),
                mark.col() + 1
            ),
        )
    }
}

/// Characters PyYAML's reader refuses (`yaml/reader.py`, NON_PRINTABLE).
static NON_PRINTABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("[^\x09\x0A\x0D\x20-\x7E\u{85}\u{A0}-\u{D7FF}\u{E000}-\u{FFFD}\u{10000}-\u{10FFFF}]")
        .expect("a valid pattern")
});

/// Loads one YAML document as `yaml.safe_load` does: `Value::Null` for an empty stream. `name`
/// is the file's, for the errors.
pub fn load(text: &str, name: &str, budget: &mut Budget) -> Result<Value, YamlError> {
    if let Some(found) = NON_PRINTABLE.find(text) {
        let c = found.as_str().chars().next().unwrap_or('\0');
        return Err(YamlError::new(
            "ReaderError",
            format!(
                "unacceptable character #x{:04x}: special characters are not allowed",
                c as u32
            ),
        ));
    }
    // every event first, within the node budget, so the last block scalar can be fixed up
    let mut parser = Parser::new_from_str(text);
    let mut events = Vec::new();
    loop {
        let (event, mark) = parser
            .next_token()
            .map_err(|e| YamlError::at(scan_error_class(e.info()), e.info(), *e.marker(), name))?;
        let end = event == Event::StreamEnd;
        events.push((event, mark));
        if end {
            break;
        }
        if events.len() > budget.limits.max_nodes {
            return Err(YamlError::limit(format!(
                "more than {} YAML nodes",
                budget.limits.max_nodes
            )));
        }
    }
    unclip_block_scalar_at_end(text, &mut events);
    let mut composer = Composer {
        name,
        budget,
        frames: Vec::new(),
        anchors: Vec::new(),
        open_anchors: Vec::new(),
        result: None,
        documents: 0,
    };
    for (event, mark) in events {
        match composer.event(event, mark)? {
            Flow::More => {}
            Flow::End => break,
        }
    }
    Ok(composer.result.unwrap_or(Value::Null))
}

/// A literal or folded block scalar that runs to the end of a file with no final line break ends
/// with no line break in PyYAML, which keeps only breaks that are there; yaml-rust2 gives it one.
/// So when the file doesn't end with a break, the last scalar is a block scalar, and every
/// non-blank line from its first is indented at least as far as that one, it loses that break.
fn unclip_block_scalar_at_end(text: &str, events: &mut [(Event, Marker)]) {
    if text.is_empty() || text.ends_with(['\n', '\r']) {
        return;
    }
    let Some((Event::Scalar(value, style, _, _), mark)) = events
        .iter_mut()
        .rev()
        .find(|(e, _)| matches!(e, Event::Scalar(..)))
    else {
        return;
    };
    if !matches!(style, TScalarStyle::Literal | TScalarStyle::Folded) || !value.ends_with('\n') {
        return;
    }
    let indent = |line: &str| line.len() - line.trim_start_matches(' ').len();
    // yaml-rust2 marks a block scalar at its first line of content
    let mut content = text
        .lines()
        .skip(mark.line().saturating_sub(1))
        .filter(|l| !l.trim().is_empty());
    let Some(first) = content.next() else {
        return;
    };
    let block = indent(first);
    if content.all(|l| indent(l) >= block) {
        value.pop();
    }
}

/// PyYAML raises a ScannerError for a malformed token and a ParserError for tokens in the wrong
/// order; yaml-rust2 raises one error type for both, so this sorts by its message.
fn scan_error_class(info: &str) -> &'static str {
    if info.contains("unknown anchor") {
        "ComposerError"
    } else if info.starts_with("while parsing")
        || info.starts_with("did not find expected")
        || info.contains("expected")
            && !info.starts_with("while scanning")
            && !info.contains("mapping values")
    {
        "ParserError"
    } else {
        "ScannerError"
    }
}

enum Flow {
    More,
    End,
}

/// A node being built, or a key that is the `<<` merge key.
enum Node {
    Value(Value),
    Merge,
}

enum Frame {
    Seq {
        anchor: usize,
        items: Vec<Value>,
        mark: Marker,
    },
    Map {
        anchor: usize,
        pairs: Vec<(Node, Value)>,
        key: Option<Node>,
        mark: Marker,
    },
}

struct Composer<'a> {
    name: &'a str,
    budget: &'a mut Budget,
    frames: Vec<Frame>,
    /// Finished anchored nodes, by anchor id.
    anchors: Vec<(usize, Value)>,
    /// Anchors whose node is still being built, for refusing a recursive alias.
    open_anchors: Vec<usize>,
    result: Option<Value>,
    documents: usize,
}

impl Composer<'_> {
    fn event(&mut self, event: Event, mark: Marker) -> Result<Flow, YamlError> {
        match event {
            Event::Nothing | Event::StreamStart | Event::DocumentEnd => {}
            Event::StreamEnd => return Ok(Flow::End),
            Event::DocumentStart => {
                self.documents += 1;
                if self.documents > 1 {
                    return Err(YamlError::at(
                        "ComposerError",
                        "expected a single document in the stream\nbut found another document",
                        mark,
                        self.name,
                    ));
                }
            }
            Event::Alias(id) => {
                if self.open_anchors.contains(&id) {
                    return Err(YamlError::limit(
                        "a recursive alias, an anchor used inside its own node".to_owned(),
                    ));
                }
                let value = self
                    .anchors
                    .iter()
                    .rev()
                    .find(|(a, _)| *a == id)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| {
                        YamlError::at("ComposerError", "found undefined alias", mark, self.name)
                    })?;
                self.budget.spend(value.nodes(), value.text_bytes())?;
                self.finish(Node::Value(value), mark)?;
            }
            Event::Scalar(text, style, anchor, tag) => {
                self.budget.spend(1, text.len())?;
                let node = construct_scalar(text, style, tag.as_ref(), mark, self.name)?;
                if anchor > 0
                    && let Node::Value(value) = &node
                {
                    self.anchors.push((anchor, value.clone()));
                }
                self.finish(node, mark)?;
            }
            Event::SequenceStart(anchor, tag) => {
                check_collection_tag(tag.as_ref(), "seq", mark, self.name)?;
                self.open(
                    Frame::Seq {
                        anchor,
                        items: Vec::new(),
                        mark,
                    },
                    anchor,
                )?;
            }
            Event::MappingStart(anchor, tag) => {
                check_collection_tag(tag.as_ref(), "map", mark, self.name)?;
                self.open(
                    Frame::Map {
                        anchor,
                        pairs: Vec::new(),
                        key: None,
                        mark,
                    },
                    anchor,
                )?;
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let frame = self.frames.pop().expect("an end has a start");
                let (anchor, value, start) = match frame {
                    Frame::Seq {
                        anchor,
                        items,
                        mark,
                    } => (anchor, Value::Seq(items), mark),
                    Frame::Map {
                        anchor,
                        pairs,
                        mark,
                        ..
                    } => (anchor, Value::Map(flatten(pairs, mark, self.name)?), mark),
                };
                if anchor > 0 {
                    self.open_anchors.retain(|a| *a != anchor);
                    self.anchors.push((anchor, value.clone()));
                }
                self.finish(Node::Value(value), start)?;
            }
        }
        Ok(Flow::More)
    }

    fn open(&mut self, frame: Frame, anchor: usize) -> Result<(), YamlError> {
        self.budget.spend(1, 0)?;
        if self.frames.len() >= self.budget.limits.max_depth {
            return Err(YamlError::limit(format!(
                "YAML nested more than {} deep",
                self.budget.limits.max_depth
            )));
        }
        if anchor > 0 {
            self.open_anchors.push(anchor);
        }
        self.frames.push(frame);
        Ok(())
    }

    /// Puts a finished node where it belongs: in the collection being built, or as the result.
    fn finish(&mut self, node: Node, mark: Marker) -> Result<(), YamlError> {
        let name = self.name;
        match self.frames.last_mut() {
            None => match node {
                Node::Value(value) => self.result = Some(value),
                Node::Merge => return Err(no_constructor("merge", mark, name)),
            },
            Some(Frame::Seq { items, .. }) => match node {
                Node::Value(value) => items.push(value),
                Node::Merge => return Err(no_constructor("merge", mark, name)),
            },
            Some(Frame::Map { pairs, key, .. }) => match key.take() {
                None => *key = Some(node),
                Some(k) => match node {
                    Node::Value(value) => pairs.push((k, value)),
                    Node::Merge => return Err(no_constructor("merge", mark, name)),
                },
            },
        }
        Ok(())
    }
}

fn no_constructor(tag: &str, mark: Marker, name: &str) -> YamlError {
    YamlError::at(
        "ConstructorError",
        format!("could not determine a constructor for the tag 'tag:yaml.org,2002:{tag}'"),
        mark,
        name,
    )
}

/// A mapping's pairs as SafeConstructor builds them: its `<<` merges first, in PyYAML's order,
/// then its own keys, a later key replacing an earlier equal one where it stood.
fn flatten(pairs: Vec<(Node, Value)>, mark: Marker, name: &str) -> Result<Map, YamlError> {
    let mut merged: Vec<(Value, Value)> = Vec::new();
    let mut own: Vec<(Value, Value)> = Vec::new();
    for (key, value) in pairs {
        match key {
            Node::Merge => match value {
                Value::Map(map) => merged.extend(map.iter().map(|(k, v)| (k.clone(), v.clone()))),
                Value::Seq(items) => {
                    let mut groups = Vec::new();
                    for item in items {
                        match item {
                            Value::Map(map) => groups
                                .push(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
                            _ => {
                                return Err(YamlError::at(
                                    "ConstructorError",
                                    "while constructing a mapping\nexpected a mapping for merging",
                                    mark,
                                    name,
                                ));
                            }
                        }
                    }
                    groups.reverse();
                    for group in groups {
                        merged.extend::<Vec<_>>(group);
                    }
                }
                _ => {
                    return Err(YamlError::at(
                        "ConstructorError",
                        "while constructing a mapping\nexpected a mapping or list of mappings for merging",
                        mark,
                        name,
                    ));
                }
            },
            Node::Value(k) => own.push((k, value)),
        }
    }
    let mut map = Map::new();
    for (k, v) in merged.into_iter().chain(own) {
        if matches!(k, Value::Seq(_) | Value::Map(_)) {
            return Err(YamlError::at(
                "ConstructorError",
                "while constructing a mapping\nfound unhashable key",
                mark,
                name,
            ));
        }
        map.insert(k, v);
    }
    Ok(map)
}

const CORE: &str = "tag:yaml.org,2002:";

/// The core tag a node names, such as `str` for `!!str`, or None for no tag.
fn tag_suffix(tag: Option<&Tag>) -> Option<String> {
    let tag = tag?;
    if tag.handle == "!!" {
        Some(tag.suffix.clone())
    } else if let Some(suffix) = format!("{}{}", tag.handle, tag.suffix).strip_prefix(CORE) {
        Some(suffix.to_owned())
    } else if tag.handle == "!" && tag.suffix.is_empty() {
        // the non-specific tag: a scalar is a string, a collection what it is
        Some(String::new())
    } else {
        Some(format!("!{}{}", tag.handle, tag.suffix))
    }
}

fn check_collection_tag(
    tag: Option<&Tag>,
    kind: &str,
    mark: Marker,
    name: &str,
) -> Result<(), YamlError> {
    match tag_suffix(tag) {
        None => Ok(()),
        Some(suffix) if suffix.is_empty() || suffix == kind => Ok(()),
        Some(suffix) => Err(unsupported_tag(&suffix, mark, name)),
    }
}

fn unsupported_tag(suffix: &str, mark: Marker, name: &str) -> YamlError {
    let tag = suffix
        .strip_prefix('!')
        .map_or_else(|| format!("{CORE}{suffix}"), str::to_owned);
    YamlError::at(
        "ConstructorError",
        format!("could not determine a constructor for the tag {tag:?}"),
        mark,
        name,
    )
}

static BOOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$")
        .expect("a valid pattern")
});
static FLOAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?",
        r"|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?",
        r"|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*",
        r"|[-+]?\.(?:inf|Inf|INF)",
        r"|\.(?:nan|NaN|NAN))$"
    ))
    .expect("a valid pattern")
});
static INT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[-+]?0b[0-1_]+",
        r"|[-+]?0[0-7_]+",
        r"|[-+]?(?:0|[1-9][0-9_]*)",
        r"|[-+]?0x[0-9a-fA-F_]+",
        r"|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$"
    ))
    .expect("a valid pattern")
});
static NULL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:~|null|Null|NULL|)$").expect("a valid pattern"));
static DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$").expect("a valid pattern"));
static TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}",
        r"|[0-9]{4}-[0-9][0-9]?-[0-9][0-9]?",
        r"(?:[Tt]|[ \t]+)[0-9][0-9]?",
        r":[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?",
        r"(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$"
    ))
    .expect("a valid pattern")
});

/// What a plain scalar resolves to, by PyYAML's implicit resolvers in their order.
fn resolve_plain(text: &str) -> &'static str {
    let first = text.chars().next();
    let starts = |set: &str| first.is_some_and(|c| set.contains(c));
    if starts("yYnNtTfFoO") && BOOL.is_match(text) {
        "bool"
    } else if starts("-+0123456789.") && FLOAT.is_match(text) {
        "float"
    } else if starts("-+0123456789") && INT.is_match(text) {
        "int"
    } else if text == "<<" {
        "merge"
    } else if (first.is_none() || starts("~nN")) && NULL.is_match(text) {
        "null"
    } else if starts("0123456789") && TIMESTAMP.is_match(text) {
        "timestamp"
    } else if text == "=" {
        "value"
    } else {
        "str"
    }
}

fn construct_scalar(
    text: String,
    style: TScalarStyle,
    tag: Option<&Tag>,
    mark: Marker,
    name: &str,
) -> Result<Node, YamlError> {
    let kind = match tag_suffix(tag) {
        Some(suffix) if suffix.is_empty() => "str".to_owned(),
        Some(suffix) => suffix,
        None if style == TScalarStyle::Plain => resolve_plain(&text).to_owned(),
        None => "str".to_owned(),
    };
    let bad = |what: &str| YamlError::new("ValueError", format!("invalid {what}: {text:?}"));
    let value = match kind.as_str() {
        "str" => Value::Str(text),
        "null" => Value::Null,
        "bool" => match text.to_lowercase().as_str() {
            "yes" | "true" | "on" => Value::Bool(true),
            "no" | "false" | "off" => Value::Bool(false),
            _ => return Err(bad("bool")),
        },
        "int" => Value::Int(construct_int(&text).ok_or_else(|| bad("int"))?),
        "float" => Value::Float(construct_float(&text).ok_or_else(|| bad("float"))?),
        "timestamp" if DATE.is_match(&text) => Value::Date(text),
        "timestamp" if TIMESTAMP.is_match(&text) => Value::DateTime(text),
        "merge" if tag.is_none() => return Ok(Node::Merge),
        other => return Err(unsupported_tag(other, mark, name)),
    };
    Ok(Node::Value(value))
}

/// SafeConstructor.construct_yaml_int.
fn construct_int(text: &str) -> Option<i128> {
    let value = text.replace('_', "");
    let (sign, digits) = match value.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, value.strip_prefix('+').unwrap_or(&value)),
    };
    let magnitude = if digits == "0" {
        0
    } else if let Some(bin) = digits.strip_prefix("0b") {
        i128::from_str_radix(bin, 2).ok()?
    } else if let Some(hex) = digits.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()?
    } else if digits.starts_with('0') {
        i128::from_str_radix(digits, 8).ok()?
    } else if digits.contains(':') {
        let mut total: i128 = 0;
        for part in digits.split(':') {
            total = total.checked_mul(60)?.checked_add(part.parse().ok()?)?;
        }
        total
    } else {
        digits.parse().ok()?
    };
    Some(sign * magnitude)
}

/// SafeConstructor.construct_yaml_float.
fn construct_float(text: &str) -> Option<f64> {
    let value = text.replace('_', "").to_lowercase();
    let (sign, digits) = match value.strip_prefix('-') {
        Some(rest) => (-1.0, rest),
        None => (1.0, value.strip_prefix('+').unwrap_or(&value)),
    };
    if digits == ".inf" {
        Some(sign * f64::INFINITY)
    } else if digits == ".nan" {
        Some(f64::NAN)
    } else if digits.contains(':') {
        let mut total = 0.0;
        for part in digits.split(':') {
            total = total * 60.0 + part.parse::<f64>().ok()?;
        }
        Some(sign * total)
    } else {
        // Python's float() takes "1." and ".5"; Rust's parse does too
        digits.parse::<f64>().ok().map(|f| sign * f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_str(text: &str) -> Result<Value, YamlError> {
        load(text, "test.yaml", &mut Budget::new(Limits::default()))
    }

    fn json(text: &str) -> serde_json::Value {
        load_str(text).unwrap().to_json()
    }

    #[test]
    fn plain_scalars_resolve_as_yaml_1_1() {
        let v = json(
            "a: yes\nb: off\nc: 0x1F\nd: 010\ne: 1_000\nf: 1:30\ng: 01:00:00:00\nh: 1e5\n\
             i: 1.5e+3\nj: ~\nk:\nl: '1'\nm: .inf\nn: 09\no: 2024-01-02\np: <<x\n",
        );
        assert_eq!(
            v,
            serde_json::json!({
                "a": true, "b": false, "c": 31, "d": 8, "e": 1000, "f": 90, "g": "01:00:00:00",
                "h": "1e5", "i": 1500.0, "j": null, "k": null, "l": "1", "m": null, "n": "09",
                "o": "2024-01-02", "p": "<<x"
            })
        );
        assert!(matches!(
            load_str("o: 2024-01-02")
                .unwrap()
                .as_map()
                .unwrap()
                .get("o"),
            Some(Value::Date(_))
        ));
    }

    #[test]
    fn merge_keys_and_duplicates_follow_pyyaml() {
        let v = json("base: &b {x: 1, y: 2}\nm:\n  <<: *b\n  y: 3\n  x: 4\n  x: 5\n");
        assert_eq!(v["m"], serde_json::json!({"x": 5, "y": 3}));
        let v = json("a: &a {x: 1}\nb: &b {x: 2, z: 1}\nm:\n  <<: [*a, *b]\n");
        assert_eq!(v["m"], serde_json::json!({"x": 1, "z": 1}));
    }

    #[test]
    fn an_alias_bomb_runs_out_of_budget() {
        let mut text = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for (i, name) in ["b", "c", "d", "e", "f", "g", "h", "i"].iter().enumerate() {
            let prev = if i == 0 {
                "a".to_owned()
            } else {
                ["b", "c", "d", "e", "f", "g", "h"][i - 1].to_owned()
            };
            text.push_str(&format!(
                "{name}: &{name} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"
            ));
        }
        let error = load_str(&text).unwrap_err();
        assert_eq!(error.class, None, "{error:?}");
        assert!(error.message.contains("nodes"), "{error:?}");
    }

    #[test]
    fn deep_nesting_is_refused() {
        let text = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(load_str(&text).is_err());
        let block: String = (0..100)
            .map(|i| format!("{}k:\n", "  ".repeat(i)))
            .collect();
        let error = load_str(&block).unwrap_err();
        assert_eq!(error.class, None, "{error:?}");
    }

    #[test]
    fn a_block_scalar_at_the_end_of_a_file_has_only_the_breaks_it_has() {
        assert_eq!(json("q: |\n  a\n  b"), serde_json::json!({"q": "a\nb"}));
        assert_eq!(json("q: |\n  a\n  b\n"), serde_json::json!({"q": "a\nb\n"}));
        assert_eq!(
            json("r:\n  q: >\n    a\n    b"),
            serde_json::json!({"r": {"q": "a b"}})
        );
        assert_eq!(
            json("q: |\n  a\nz: x"),
            serde_json::json!({"q": "a\n", "z": "x"})
        );
        assert_eq!(
            json("q: |\n  a\n    b\n  c"),
            serde_json::json!({"q": "a\n  b\nc"})
        );
        assert_eq!(json("q: |\n  a\n\n  "), serde_json::json!({"q": "a\n"}));
    }

    #[test]
    fn errors_have_pyyaml_classes() {
        assert_eq!(
            load_str("a: [b").unwrap_err().class,
            Some("ParserError"),
            "{:?}",
            load_str("a: [b")
        );
        assert_eq!(
            load_str("a: *nope").unwrap_err().class,
            Some("ComposerError")
        );
        assert_eq!(
            load_str("a: 1\n---\nb: 2").unwrap_err().class,
            Some("ComposerError")
        );
        assert_eq!(
            load_str("? [a]\n: 1").unwrap_err().class,
            Some("ConstructorError")
        );
        assert_eq!(load_str("a: \u{1}").unwrap_err().class, Some("ReaderError"));
        assert_eq!(
            load_str("a: =").unwrap_err().class,
            Some("ConstructorError")
        );
        assert!(matches!(load_str(""), Ok(Value::Null)));
    }
}
