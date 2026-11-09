//! BeautifulSoup 4.15.0's `BeautifulSoup(text, "lxml")`: its tree ([`parse`]) and its
//! `get_text()` ([`get_text`]).
//!
//! bs4's lxml builder feeds the text to `etree.HTMLParser(target=builder, recover=True)`, lxml's
//! feed parser over libxml2's HTML push parser, and builds its tree from the events: a start or
//! an end tag, text, a comment, a processing instruction, a doctype. So this drives the same push
//! parser with the same SAX callbacks lxml's target mode installs, and keeps what bs4 keeps of the
//! events:
//!
//! - the text between two events is one string;
//! - outside `<pre>` and `<textarea>`, a string of nothing but ASCII spaces becomes `"\n"` if it
//!   holds a newline and `" "` if not;
//! - a string whose innermost open container is `<script>`, `<style>`, `<template>`, `<rt>` or
//!   `<rp>`, a comment, a processing instruction and a doctype aren't plain strings, which
//!   `get_text()` leaves out;
//! - an end tag pops bs4's stack to the newest open tag of that name, and does nothing when none
//!   is open; a tag name `{ns}name` is `name`, as bs4's `_getNsTag` splits it;
//! - an element's attributes are lxml's dict of them, a later one of a name replacing the value of
//!   an earlier one in its place, and the HTML builder's multi-valued attributes, such as `class`,
//!   are split on whitespace as `\S+` finds the parts.
//!
//! Nodes are kept in the order they were made, which is document order, so a document's
//! `find_all(True)` is its elements in that order and nothing here recurses.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr;

use ace_pycompat::pystr::is_space;

use crate::ffi::*;

/// What a string is, by the container it's in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    /// A `NavigableString`, which `get_text()` joins.
    Plain,
    /// The text of a `<script>`, `<style>`, `<template>`, `<rt>` or `<rp>`.
    Container,
    Comment,
    ProcessingInstruction,
    Doctype,
}

/// What [`Builder`] is told about each string bs4 makes.
trait Builder {
    fn open(&mut self, name: String, attrs: Vec<(String, String)>);
    fn string(&mut self, text: String, kind: StringKind);
    fn close(&mut self);
}

struct Soup<B> {
    /// The open tags, root first: name, container, preserves whitespace.
    stack: Vec<(String, bool, bool)>,
    containers: usize,
    preserves: usize,
    current: String,
    /// Whether `handle_data` was called since the last string, even with nothing: bs4's
    /// `current_data` is a list, and a list holding `""` makes a string.
    pending: bool,
    builder: B,
    /// lxml decodes each piece of text strictly; past a piece that isn't UTF-8 its handler
    /// raises and the parser stops.
    failed: bool,
}

const ASCII_SPACES: [char; 5] = [' ', '\n', '\t', '\x0c', '\r'];
const CONTAINERS: [&str; 5] = ["rt", "rp", "style", "script", "template"];
const PRESERVE: [&str; 2] = ["pre", "textarea"];

impl<B: Builder> Soup<B> {
    fn new(builder: B) -> Self {
        Soup {
            stack: vec![("[document]".to_owned(), false, false)],
            containers: 0,
            preserves: 0,
            current: String::new(),
            pending: false,
            builder,
            failed: false,
        }
    }

    /// `endData(containerClass)`.
    fn end_data(&mut self, kind: Option<StringKind>) {
        if !self.pending {
            return;
        }
        self.pending = false;
        let mut data = std::mem::take(&mut self.current);
        if self.preserves == 0 && data.chars().all(|c| ASCII_SPACES.contains(&c)) {
            data = if data.contains('\n') { "\n" } else { " " }.to_owned();
        }
        let kind = kind.unwrap_or(if self.containers > 0 {
            StringKind::Container
        } else {
            StringKind::Plain
        });
        self.builder.string(data, kind);
    }

    fn start(&mut self, name: &str, attrs: Vec<(String, String)>) {
        self.end_data(None);
        let name = ns_tag(name).to_owned();
        let container = CONTAINERS.contains(&name.as_str());
        let preserve = PRESERVE.contains(&name.as_str());
        self.containers += usize::from(container);
        self.preserves += usize::from(preserve);
        self.builder.open(name.clone(), attrs);
        self.stack.push((name, container, preserve));
    }

    fn pop(&mut self) {
        if self.stack.len() > 1
            && let Some((_, container, preserve)) = self.stack.pop()
        {
            self.containers -= usize::from(container);
            self.preserves -= usize::from(preserve);
            self.builder.close();
        }
    }

    /// `handle_endtag`: `_popToTag(name)`.
    fn end(&mut self, name: &str) {
        self.end_data(None);
        let name = ns_tag(name);
        if !self.stack[1..].iter().any(|(open, _, _)| open == name) {
            return;
        }
        while self.stack.len() > 1 {
            let found = self.stack.last().is_some_and(|(open, _, _)| open == name);
            self.pop();
            if found {
                break;
            }
        }
    }

    fn data(&mut self, data: &[u8]) {
        match std::str::from_utf8(data) {
            Ok(text) => {
                self.current.push_str(text);
                self.pending = true;
            }
            Err(_) => self.failed = true,
        }
    }

    /// A comment, a processing instruction or a doctype: what came before is a string, and what
    /// it holds is one of its own kind.
    fn other(&mut self, data: String, kind: StringKind) {
        self.end_data(None);
        self.current.push_str(&data);
        self.pending = true;
        self.end_data(Some(kind));
    }

    /// `BeautifulSoup._feed`'s end: the last string, then every open tag closed.
    fn finish(mut self) -> Option<B> {
        if self.failed {
            return None;
        }
        self.end_data(None);
        while self.stack.len() > 1 {
            self.pop();
        }
        Some(self.builder)
    }
}

/// bs4's `_getNsTag`: `{ns}name` is `name`.
fn ns_tag(tag: &str) -> &str {
    if let Some(rest) = tag.strip_prefix('{')
        && let Some((_, name)) = rest.split_once('}')
    {
        return name;
    }
    tag
}

unsafe fn soup<'a, B>(ctx: *mut c_void) -> &'a mut Soup<B> {
    unsafe { &mut *(ctx as *mut Soup<B>) }
}

unsafe fn text_of(s: *const xmlChar) -> String {
    if s.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { CStr::from_ptr(s as *const c_char) }.to_bytes()).into_owned()
}

/// lxml's `funicode`, which raises on bytes that aren't UTF-8.
unsafe fn strict_text_of(s: *const xmlChar) -> Option<String> {
    if s.is_null() {
        return Some(String::new());
    }
    let bytes = unsafe { CStr::from_ptr(s as *const c_char) }.to_bytes();
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// `_handleSaxTargetStartNoNs`'s attribute dict: each name and value, None as `""`, a later
/// value of a name replacing the earlier one in its place.
unsafe fn attributes_of(mut atts: *mut *const xmlChar) -> Option<Vec<(String, String)>> {
    let mut attrs: Vec<(String, String)> = Vec::new();
    if atts.is_null() {
        return Some(attrs);
    }
    unsafe {
        while !(*atts).is_null() {
            let name = strict_text_of(*atts)?;
            let value = strict_text_of(*atts.add(1))?;
            match attrs.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1 = value,
                None => attrs.push((name, value)),
            }
            atts = atts.add(2);
        }
    }
    Some(attrs)
}

unsafe extern "C" fn on_start<B: Builder>(
    ctx: *mut c_void,
    name: *const xmlChar,
    atts: *mut *const xmlChar,
) {
    let soup = unsafe { soup::<B>(ctx) };
    if soup.failed {
        return;
    }
    match unsafe { (strict_text_of(name), attributes_of(atts)) } {
        (Some(name), Some(attrs)) => soup.start(&name, attrs),
        _ => soup.failed = true,
    }
}

unsafe extern "C" fn on_end<B: Builder>(ctx: *mut c_void, name: *const xmlChar) {
    let soup = unsafe { soup::<B>(ctx) };
    if !soup.failed {
        soup.end(&unsafe { text_of(name) });
    }
}

unsafe extern "C" fn on_data<B: Builder>(ctx: *mut c_void, data: *const xmlChar, len: c_int) {
    let soup = unsafe { soup::<B>(ctx) };
    if soup.failed || data.is_null() {
        return;
    }
    let len = usize::try_from(len).unwrap_or(0);
    soup.data(unsafe { std::slice::from_raw_parts(data, len) });
}

unsafe extern "C" fn on_comment<B: Builder>(ctx: *mut c_void, text: *const xmlChar) {
    let soup = unsafe { soup::<B>(ctx) };
    if !soup.failed {
        soup.other(unsafe { text_of(text) }, StringKind::Comment);
    }
}

unsafe extern "C" fn on_pi<B: Builder>(
    ctx: *mut c_void,
    target: *const xmlChar,
    data: *const xmlChar,
) {
    let soup = unsafe { soup::<B>(ctx) };
    if !soup.failed {
        let text = format!("{} {}", unsafe { text_of(target) }, unsafe {
            text_of(data)
        });
        soup.other(text, StringKind::ProcessingInstruction);
    }
}

/// `doctype`: `Doctype._string_for_name_and_ids(name, pub_id, system_id)` as a string of its own.
unsafe extern "C" fn on_doctype<B: Builder>(
    ctx: *mut c_void,
    name: *const xmlChar,
    public_id: *const xmlChar,
    system_id: *const xmlChar,
) {
    let soup = unsafe { soup::<B>(ctx) };
    if soup.failed {
        return;
    }
    let (name, public_id, system_id) = unsafe {
        (
            text_of(name),
            (!public_id.is_null()).then(|| text_of(public_id)),
            (!system_id.is_null()).then(|| text_of(system_id)),
        )
    };
    let mut value = name;
    if let Some(public_id) = public_id {
        value.push_str(&format!(" PUBLIC \"{public_id}\""));
        if let Some(system_id) = &system_id {
            value.push_str(&format!(" \"{system_id}\""));
        }
    } else if let Some(system_id) = system_id {
        value.push_str(&format!(" SYSTEM \"{system_id}\""));
    }
    soup.other(value, StringKind::Doctype);
}

unsafe extern "C" fn on_document(_: *mut c_void) {}

unsafe extern "C" fn ignore_error(_: *mut c_void, _: *const xmlError) {}

/// The characters lxml's feed parser hands libxml2 at a time: `2**19` of the str, as UTF-8.
const CHUNK_CHARS: usize = 1 << 19;

/// Feeds `text` through libxml2's HTML push parser into a bs4 builder. None where bs4 would
/// raise.
fn feed<B: Builder>(text: &str, builder: B) -> Option<B> {
    crate::init();
    // bs4's prepare_markup drops a leading byte order mark from a str
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut state = Soup::new(builder);
    unsafe {
        let mut sax: xmlSAXHandler = std::mem::zeroed();
        init_html_sax(&mut sax);
        sax.initialized = XML_SAX2_MAGIC;
        sax.startDocument = Some(on_document);
        sax.endDocument = Some(on_document);
        sax.setDocumentLocator = ptr::null_mut();
        sax.getEntity = ptr::null_mut();
        sax.startElement = Some(on_start::<B>);
        sax.endElement = Some(on_end::<B>);
        sax.characters = Some(on_data::<B>);
        sax.cdataBlock = Some(on_data::<B>);
        sax.ignorableWhitespace = None;
        sax.comment = Some(on_comment::<B>);
        sax.processingInstruction = Some(on_pi::<B>);
        sax.internalSubset = Some(on_doctype::<B>);
        sax.startElementNs = ptr::null_mut();
        sax.endElementNs = ptr::null_mut();
        sax.warning = ptr::null_mut();
        sax.error = ptr::null_mut();
        sax.fatalError = ptr::null_mut();
        sax.serror = Some(ignore_error);
        let ctxt = htmlCreatePushParserCtxt(
            &sax,
            &mut state as *mut Soup<B> as *mut c_void,
            ptr::null(),
            0,
            ptr::null(),
            XML_CHAR_ENCODING_UTF8,
        );
        if ctxt.is_null() {
            return None;
        }
        htmlCtxtUseOptions(
            ctxt,
            HTML_PARSE_RECOVER | HTML_PARSE_NONET | HTML_PARSE_COMPACT,
        );
        let mut rest = text;
        while !rest.is_empty() && !state.failed {
            let end = rest
                .char_indices()
                .nth(CHUNK_CHARS)
                .map_or(rest.len(), |(i, _)| i);
            let (chunk, after) = rest.split_at(end);
            htmlParseChunk(
                ctxt,
                chunk.as_ptr() as *const c_char,
                c_int::try_from(chunk.len()).unwrap_or(c_int::MAX),
                0,
            );
            rest = after;
        }
        if !state.failed {
            htmlParseChunk(ctxt, ptr::null(), 0, 1);
        }
        htmlFreeParserCtxt(ctxt);
    }
    state.finish()
}

/// Joins the plain strings, for `get_text()`.
#[derive(Default)]
struct Text(String);

impl Builder for Text {
    fn open(&mut self, _: String, _: Vec<(String, String)>) {}

    fn string(&mut self, text: String, kind: StringKind) {
        if kind == StringKind::Plain {
            self.0.push_str(&text);
        }
    }

    fn close(&mut self) {}
}

/// `BeautifulSoup(text, "lxml").get_text()`. None where bs4 would raise, which ace3's IOC
/// module answers by using the text as it is.
pub fn get_text(text: &str) -> Option<String> {
    feed(text, Text::default()).map(|text| text.0)
}

/// An attribute's value: a string, or the parts of one of the HTML builder's multi-valued
/// attributes, which bs4 keeps as a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Text(String),
    List(Vec<String>),
}

impl AttrValue {
    /// `str(value)` for a string, `" ".join(value)` for a list.
    pub fn joined(&self) -> String {
        match self {
            AttrValue::Text(text) => text.clone(),
            AttrValue::List(parts) => parts.join(" "),
        }
    }

    /// The value as a string, None for a list.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            AttrValue::Text(text) => Some(text),
            AttrValue::List(_) => None,
        }
    }
}

/// `HTMLTreeBuilder.DEFAULT_CDATA_LIST_ATTRIBUTES`.
fn is_multi_valued(tag: &str, attr: &str) -> bool {
    if matches!(attr, "class" | "accesskey" | "dropzone") {
        return true;
    }
    let tag = tag.to_lowercase();
    match tag.as_str() {
        "a" | "link" => matches!(attr, "rel" | "rev"),
        "td" | "th" => attr == "headers",
        "form" => attr == "accept-charset",
        "object" => attr == "archive",
        "area" => attr == "rel",
        "icon" => attr == "sizes",
        "iframe" => attr == "sandbox",
        "output" => attr == "for",
        _ => false,
    }
}

/// One node of a [`Tree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// The `BeautifulSoup` object itself.
    Document,
    /// A `Tag`: its name and its attributes in order.
    Element {
        name: String,
        attrs: Vec<(String, AttrValue)>,
    },
    /// A `NavigableString` or one of its kinds.
    Text { text: String, kind: StringKind },
}

#[derive(Debug, Clone)]
struct Slot {
    node: Node,
    parent: Option<usize>,
    /// How many children, the first of them, and the first that's a string.
    children: usize,
    first_child: Option<usize>,
    first_string: Option<usize>,
}

/// The tree `BeautifulSoup(text, "lxml")` builds, its nodes in document order. Node 0 is the
/// document.
#[derive(Debug, Clone)]
pub struct Tree {
    slots: Vec<Slot>,
}

/// Builds the [`Tree`].
struct TreeBuilder {
    slots: Vec<Slot>,
    open: Vec<usize>,
}

impl TreeBuilder {
    fn add(&mut self, node: Node) -> usize {
        let parent = *self.open.last().expect("the document is open");
        let index = self.slots.len();
        let is_string = matches!(node, Node::Text { .. });
        self.slots.push(Slot {
            node,
            parent: Some(parent),
            children: 0,
            first_child: None,
            first_string: None,
        });
        let parent = &mut self.slots[parent];
        parent.children += 1;
        parent.first_child.get_or_insert(index);
        if is_string {
            parent.first_string.get_or_insert(index);
        }
        index
    }
}

impl Builder for TreeBuilder {
    fn open(&mut self, name: String, attrs: Vec<(String, String)>) {
        let attrs = attrs
            .into_iter()
            .map(|(attr, value)| {
                let value = if is_multi_valued(&name, &attr) {
                    AttrValue::List(
                        value
                            .split(is_space)
                            .filter(|part| !part.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    )
                } else {
                    AttrValue::Text(value)
                };
                (attr, value)
            })
            .collect();
        let index = self.add(Node::Element { name, attrs });
        self.open.push(index);
    }

    fn string(&mut self, text: String, kind: StringKind) {
        self.add(Node::Text { text, kind });
    }

    fn close(&mut self) {
        self.open.pop();
    }
}

/// `BeautifulSoup(text, "lxml")`. None where bs4 would raise `ParserRejectedMarkup`.
pub fn parse(text: &str) -> Option<Tree> {
    let builder = TreeBuilder {
        slots: vec![Slot {
            node: Node::Document,
            parent: None,
            children: 0,
            first_child: None,
            first_string: None,
        }],
        open: vec![0],
    };
    feed(text, builder).map(|builder| Tree {
        slots: builder.slots,
    })
}

impl Tree {
    /// How many nodes, the document included.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Always false: the document is a node.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn node(&self, index: usize) -> &Node {
        &self.slots[index].node
    }

    pub fn parent(&self, index: usize) -> Option<usize> {
        self.slots[index].parent
    }

    /// `find_all(True)`: every element, in document order.
    pub fn elements(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.slots.len()).filter(|&i| matches!(self.slots[i].node, Node::Element { .. }))
    }

    /// `find_all(name)`: the elements of that name, in document order.
    pub fn elements_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = usize> + 'a {
        self.elements().filter(
            move |&i| matches!(&self.slots[i].node, Node::Element { name: n, .. } if n == name),
        )
    }

    /// An element's name.
    pub fn name(&self, index: usize) -> Option<&str> {
        match &self.slots[index].node {
            Node::Element { name, .. } => Some(name),
            _ => None,
        }
    }

    /// An element's attributes, in order.
    pub fn attrs(&self, index: usize) -> &[(String, AttrValue)] {
        match &self.slots[index].node {
            Node::Element { attrs, .. } => attrs,
            _ => &[],
        }
    }

    /// `tag.get(attr)`.
    pub fn get(&self, index: usize, attr: &str) -> Option<&AttrValue> {
        self.attrs(index)
            .iter()
            .find(|(name, _)| name == attr)
            .map(|(_, value)| value)
    }

    /// A string node's text.
    pub fn text(&self, index: usize) -> Option<&str> {
        match &self.slots[index].node {
            Node::Text { text, .. } => Some(text),
            _ => None,
        }
    }

    /// `tag.find(string=True, recursive=False)`: the first child that's a string of any kind.
    pub fn own_string(&self, index: usize) -> Option<&str> {
        self.slots[index]
            .first_string
            .and_then(|child| self.text(child))
    }

    /// `tag.string`: the one child's string, or the string of the one child's one child, and so
    /// on down.
    pub fn string(&self, mut index: usize) -> Option<&str> {
        loop {
            let slot = &self.slots[index];
            if slot.children != 1 {
                return None;
            }
            let child = slot.first_child?;
            match &self.slots[child].node {
                Node::Text { text, .. } => return Some(text),
                Node::Element { .. } => index = child,
                Node::Document => return None,
            }
        }
    }
}

const XML_CHAR_ENCODING_UTF8: c_int = 1;
pub(crate) const XML_SAX2_MAGIC: u32 = 0xDEED_BEAF;

unsafe extern "C" {
    fn xmlSAX2InitHtmlDefaultSAXHandler(hdlr: *mut xmlSAXHandler);
}

/// libxml2's default HTML handlers, as `htmlDefaultSAXHandler` holds them.
pub(crate) unsafe fn init_html_sax(sax: &mut xmlSAXHandler) {
    unsafe { xmlSAX2InitHtmlDefaultSAXHandler(sax) };
}
