//! BeautifulSoup 4.15.0's `BeautifulSoup(text, "lxml").get_text()`.
//!
//! bs4's lxml builder feeds the text to `etree.HTMLParser(target=builder, recover=True)`, lxml's
//! feed parser over libxml2's HTML push parser, and builds its tree from the events: a start or
//! an end tag, text, a comment, a processing instruction, a doctype. `get_text()` joins the
//! tree's plain strings. So this drives the same push parser with the same SAX callbacks lxml's
//! target mode installs, and keeps what bs4 keeps of the events:
//!
//! - the text between two events is one string;
//! - outside `<pre>` and `<textarea>`, a string of nothing but ASCII spaces becomes `"\n"` if it
//!   holds a newline and `" "` if not;
//! - a string whose innermost open container is `<script>`, `<style>`, `<template>`, `<rt>` or
//!   `<rp>`, a comment, a processing instruction and a doctype aren't plain strings;
//! - an end tag pops bs4's stack to the newest open tag of that name, and does nothing when none
//!   is open; a tag name `{ns}name` is `name`, as bs4's `_getNsTag` splits it.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr;

use crate::ffi::*;

/// What a string is, by the container it's in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    Other,
}

#[derive(Default)]
struct Soup {
    /// The open tags, root first: name, container, preserves whitespace.
    stack: Vec<(String, bool, bool)>,
    containers: usize,
    preserves: usize,
    current: String,
    text: String,
    /// lxml decodes each piece of text strictly; past a piece that isn't UTF-8 its handler
    /// raises and the parser stops.
    failed: bool,
}

const ASCII_SPACES: [char; 5] = [' ', '\n', '\t', '\x0c', '\r'];
const CONTAINERS: [&str; 5] = ["rt", "rp", "style", "script", "template"];
const PRESERVE: [&str; 2] = ["pre", "textarea"];

impl Soup {
    /// `endData(containerClass)`.
    fn end_data(&mut self, kind: Option<Kind>) {
        if self.current.is_empty() {
            return;
        }
        let mut data = std::mem::take(&mut self.current);
        if self.preserves == 0 && data.chars().all(|c| ASCII_SPACES.contains(&c)) {
            data = if data.contains('\n') { "\n" } else { " " }.to_owned();
        }
        let kind = kind.unwrap_or(if self.containers > 0 {
            Kind::Other
        } else {
            Kind::Plain
        });
        if kind == Kind::Plain {
            self.text.push_str(&data);
        }
    }

    fn start(&mut self, name: &str) {
        self.end_data(None);
        let name = ns_tag(name).to_owned();
        let container = CONTAINERS.contains(&name.as_str());
        let preserve = PRESERVE.contains(&name.as_str());
        self.containers += usize::from(container);
        self.preserves += usize::from(preserve);
        self.stack.push((name, container, preserve));
    }

    fn pop(&mut self) {
        if let Some((_, container, preserve)) = self.stack.pop() {
            self.containers -= usize::from(container);
            self.preserves -= usize::from(preserve);
        }
    }

    /// `handle_endtag`: `_popToTag(name)`.
    fn end(&mut self, name: &str) {
        self.end_data(None);
        let name = ns_tag(name);
        if !self.stack.iter().any(|(open, _, _)| open == name) {
            return;
        }
        while let Some((open, _, _)) = self.stack.last() {
            let found = open == name;
            self.pop();
            if found {
                break;
            }
        }
    }

    fn data(&mut self, data: &[u8]) {
        match std::str::from_utf8(data) {
            Ok(text) => self.current.push_str(text),
            Err(_) => self.failed = true,
        }
    }

    /// A comment, a processing instruction or a doctype: what came before is a string, and what
    /// it holds isn't plain.
    fn other(&mut self, data: Option<String>) {
        self.end_data(None);
        if let Some(data) = data {
            self.current.push_str(&data);
            self.end_data(Some(Kind::Other));
        }
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

unsafe fn soup<'a>(ctx: *mut c_void) -> &'a mut Soup {
    unsafe { &mut *(ctx as *mut Soup) }
}

unsafe fn text_of(s: *const xmlChar) -> String {
    if s.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { CStr::from_ptr(s as *const c_char) }.to_bytes()).into_owned()
}

unsafe extern "C" fn on_start(ctx: *mut c_void, name: *const xmlChar, _: *mut *const xmlChar) {
    let soup = unsafe { soup(ctx) };
    if !soup.failed {
        soup.start(&unsafe { text_of(name) });
    }
}

unsafe extern "C" fn on_end(ctx: *mut c_void, name: *const xmlChar) {
    let soup = unsafe { soup(ctx) };
    if !soup.failed {
        soup.end(&unsafe { text_of(name) });
    }
}

unsafe extern "C" fn on_data(ctx: *mut c_void, data: *const xmlChar, len: c_int) {
    let soup = unsafe { soup(ctx) };
    if soup.failed || data.is_null() {
        return;
    }
    let len = usize::try_from(len).unwrap_or(0);
    soup.data(unsafe { std::slice::from_raw_parts(data, len) });
}

unsafe extern "C" fn on_comment(ctx: *mut c_void, text: *const xmlChar) {
    let soup = unsafe { soup(ctx) };
    if !soup.failed {
        soup.other(Some(unsafe { text_of(text) }));
    }
}

unsafe extern "C" fn on_pi(ctx: *mut c_void, target: *const xmlChar, data: *const xmlChar) {
    let soup = unsafe { soup(ctx) };
    if !soup.failed {
        let text = format!("{} {}", unsafe { text_of(target) }, unsafe {
            text_of(data)
        });
        soup.other(Some(text));
    }
}

unsafe extern "C" fn on_doctype(
    ctx: *mut c_void,
    _: *const xmlChar,
    _: *const xmlChar,
    _: *const xmlChar,
) {
    let soup = unsafe { soup(ctx) };
    if !soup.failed {
        soup.other(Some(String::new()));
    }
}

unsafe extern "C" fn on_document(_: *mut c_void) {}

unsafe extern "C" fn ignore_error(_: *mut c_void, _: *const xmlError) {}

/// The characters lxml's feed parser hands libxml2 at a time: `2**19` of the str, as UTF-8.
const CHUNK_CHARS: usize = 1 << 19;

/// `BeautifulSoup(text, "lxml").get_text()`. None where bs4 would raise, which ace3's IOC
/// module answers by using the text as it is.
pub fn get_text(text: &str) -> Option<String> {
    crate::init();
    // bs4's prepare_markup drops a leading byte order mark from a str
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut state = Soup {
        stack: vec![("[document]".to_owned(), false, false)],
        ..Soup::default()
    };
    unsafe {
        let mut sax: xmlSAXHandler = std::mem::zeroed();
        init_html_sax(&mut sax);
        sax.initialized = XML_SAX2_MAGIC;
        sax.startDocument = Some(on_document);
        sax.endDocument = Some(on_document);
        sax.setDocumentLocator = ptr::null_mut();
        sax.getEntity = ptr::null_mut();
        sax.startElement = Some(on_start);
        sax.endElement = Some(on_end);
        sax.characters = Some(on_data);
        sax.cdataBlock = Some(on_data);
        sax.ignorableWhitespace = None;
        sax.comment = Some(on_comment);
        sax.processingInstruction = Some(on_pi);
        sax.internalSubset = Some(on_doctype);
        sax.startElementNs = ptr::null_mut();
        sax.endElementNs = ptr::null_mut();
        sax.warning = ptr::null_mut();
        sax.error = ptr::null_mut();
        sax.fatalError = ptr::null_mut();
        sax.serror = Some(ignore_error);
        let ctxt = htmlCreatePushParserCtxt(
            &sax,
            &mut state as *mut Soup as *mut c_void,
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
    if state.failed {
        return None;
    }
    // BeautifulSoup._feed: the last string, then every open tag closed
    state.end_data(None);
    Some(state.text)
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
