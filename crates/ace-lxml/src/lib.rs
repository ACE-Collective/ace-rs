//! libxml2 2.14.6, built from `vendor/libxml2/` as lxml 6.1.3's wheels bundle it, and what lxml
//! does with it for the code ported here: parsing HTML as `etree.HTMLParser(encoding="utf-8",
//! default_doctype=False)` does, lxml's view of the tree (`text`, `tail`, `attrib`, `iter`,
//! `iterdescendants`, `remove`, `append`) and `etree.tostring` with the `html` and `text`
//! methods. [`soup`] is BeautifulSoup 4.15's `get_text()` over its lxml builder.
//!
//! libxml2 does the parsing and the serializing itself, so the tree and the text are libxml2's.
//! The lxml layer here is a port of lxml's Cython (`apihelpers.pxi`, `etree.pyx`,
//! `serializer.pxi`), calling the same libxml2 functions in the same order.
//!
//! The parser runs on attacker bytes. It is C, so it runs only in a contained task process
//! (PLAN.md 2.18), as every parser module does.

mod ffi;
pub mod soup;
pub mod target;

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::sync::Once;

use ffi::*;

static INIT: Once = Once::new();

/// libxml2's global setup, once per process, as lxml's import does.
fn init() {
    INIT.call_once(|| unsafe { xmlInitParser() });
}

/// What lxml raises where Python code would see an exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LxmlError {
    /// `XMLSyntaxError`: libxml2 returned no document.
    NoDocument,
    /// `ValueError`, with lxml's message.
    Value(&'static str),
    /// `MemoryError`, or a libxml2 allocation that failed.
    Memory,
}

impl fmt::Display for LxmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LxmlError::NoDocument => f.write_str("XMLSyntaxError: libxml2 returned no document"),
            LxmlError::Value(message) => write!(f, "ValueError: {message}"),
            LxmlError::Memory => f.write_str("MemoryError"),
        }
    }
}

impl std::error::Error for LxmlError {}

unsafe extern "C" fn ignore_error(_: *mut c_void, _: *const xmlError) {}

/// What `htmlCtxtReadIO` reads from: lxml's `_FileReaderContext` over a `BytesIO`, which hands
/// libxml2 as many bytes as it asks for.
struct Reader<'b> {
    bytes: &'b [u8],
    at: usize,
}

unsafe extern "C" fn read_callback(context: *mut c_void, buffer: *mut c_char, len: c_int) -> c_int {
    let reader = unsafe { &mut *(context as *mut Reader<'_>) };
    let wanted = usize::try_from(len).unwrap_or(0);
    let n = wanted.min(reader.bytes.len() - reader.at);
    unsafe {
        ptr::copy_nonoverlapping(reader.bytes.as_ptr().add(reader.at), buffer.cast::<u8>(), n);
    }
    reader.at += n;
    c_int::try_from(n).unwrap_or(0)
}

// `htmlCtxtReadIO`, as the vendored HTMLparser.h declares it.
unsafe extern "C" {
    fn htmlCtxtReadIO(
        ctxt: *mut xmlParserCtxt,
        ioread: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int>,
        ioclose: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
        ioctx: *mut c_void,
        url: *const c_char,
        encoding: *const c_char,
        options: c_int,
    ) -> *mut xmlDoc;
}

/// lxml's `_HTML_DEFAULT_PARSE_OPTIONS` with `default_doctype=False`.
const HTML_OPTIONS: c_int =
    HTML_PARSE_RECOVER | HTML_PARSE_NONET | HTML_PARSE_COMPACT | HTML_PARSE_NODEFDTD;

/// A parsed HTML document and the nodes taken out of it, which live until it's dropped, as
/// lxml keeps a removed element while Python holds it.
pub struct Document {
    doc: *mut xmlDoc,
    detached: RefCell<Vec<*mut xmlNode>>,
    /// `_Document._ns_counter`.
    ns_counter: Cell<u32>,
}

/// lxml's `_DEFAULT_NAMESPACE_PREFIXES`.
const DEFAULT_PREFIXES: &[(&str, &str)] = &[
    ("http://www.w3.org/XML/1998/namespace", "xml"),
    ("http://www.w3.org/1999/xhtml", "html"),
    ("http://www.w3.org/1999/XSL/Transform", "xsl"),
    ("http://www.w3.org/1999/02/22-rdf-syntax-ns#", "rdf"),
    ("http://schemas.xmlsoap.org/wsdl/", "wsdl"),
    ("http://www.w3.org/2001/XMLSchema", "xs"),
    ("http://www.w3.org/2001/XMLSchema-instance", "xsi"),
    ("http://purl.org/dc/elements/1.1/", "dc"),
    ("http://codespeak.net/lxml/objectify/pytype", "py"),
];

impl Drop for Document {
    fn drop(&mut self) {
        unsafe {
            for node in self.detached.borrow().iter() {
                // a detached node put back in the tree is the document's again
                if (**node).parent.is_null() {
                    xmlFreeNode(*node);
                }
            }
            xmlFreeDoc(self.doc);
        }
    }
}

impl Document {
    /// `etree.parse(BytesIO(bytes), etree.HTMLParser(encoding="utf-8", default_doctype=False))`.
    /// The declared encoding wins over a `<meta charset>`, as in lxml.
    pub fn parse_html(bytes: &[u8]) -> Result<Document, LxmlError> {
        init();
        unsafe {
            // lxml's HTML context: libxml2's default HTML handlers on SAX2's magic, without the
            // namespace callbacks, and without cdataBlock, as HTMLParser's strip_cdata (always on)
            // sets it, so raw text such as an iframe's is a text node and serializes escaped
            let mut sax: xmlSAXHandler = std::mem::zeroed();
            soup::init_html_sax(&mut sax);
            sax.initialized = soup::XML_SAX2_MAGIC;
            sax.startElementNs = ptr::null_mut();
            sax.endElementNs = ptr::null_mut();
            sax.cdataBlock = None;
            sax.serror = Some(ignore_error);
            let ctxt = htmlNewSAXParserCtxt(&sax, ptr::null_mut());
            if ctxt.is_null() {
                return Err(LxmlError::Memory);
            }
            xmlCtxtSetErrorHandler(ctxt, Some(ignore_error), ptr::null_mut());
            let mut reader = Reader { bytes, at: 0 };
            let doc = htmlCtxtReadIO(
                ctxt,
                Some(read_callback),
                None,
                &mut reader as *mut Reader<'_> as *mut c_void,
                ptr::null(),
                c"utf-8".as_ptr(),
                HTML_OPTIONS,
            );
            htmlFreeParserCtxt(ctxt);
            if doc.is_null() {
                return Err(LxmlError::NoDocument);
            }
            Ok(Document {
                doc,
                detached: RefCell::new(Vec::new()),
                ns_counter: Cell::new(0),
            })
        }
    }

    /// `buildNewPrefix`, NUL-terminated.
    fn new_prefix(&self) -> String {
        let n = self.ns_counter.get();
        self.ns_counter.set(n.wrapping_add(1));
        format!("ns{n}\0")
    }

    /// `tree.getroot()`.
    pub fn root(&self) -> Option<Node<'_>> {
        let root = unsafe { xmlDocGetRootElement(self.doc) };
        Node::wrap(root, self)
    }

    /// `etree.tostring(tree, encoding="unicode", method="html")`, lxml's `_writeNodeToBuffer`
    /// for an `_ElementTree`: the comments before the doctype, the doctype if it names the root,
    /// the comments before the root, the root, its tail and the comments after it.
    pub fn tostring_html(&self) -> Result<String, LxmlError> {
        let Some(root) = self.root() else {
            return Ok(String::new());
        };
        let bytes = unsafe { OutputBuffer::new()?.write_tree(self.doc, root.ptr) };
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// `etree.tostring(tree, encoding="utf-8", method="text")`: the root's text content and
    /// its tail.
    pub fn tostring_text(&self) -> Result<Vec<u8>, LxmlError> {
        let Some(root) = self.root() else {
            return Ok(Vec::new());
        };
        unsafe { text_to_string(root.ptr) }
    }
}

/// `serializer.pxi`'s `_textToString(c_node, encoding, with_tail=True)`.
unsafe fn text_to_string(node: *mut xmlNode) -> Result<Vec<u8>, LxmlError> {
    unsafe {
        let buffer = xmlBufferCreate();
        if buffer.is_null() {
            return Err(LxmlError::Memory);
        }
        let result = xmlNodeBufGetContent(buffer, node);
        let mut text = text_node_or_skip((*node).next);
        while !text.is_null() {
            xmlBufferWriteChar(buffer, (*text).content as *const c_char);
            text = text_node_or_skip((*text).next);
        }
        let content = xmlBufferContent(buffer);
        if result < 0 || content.is_null() {
            xmlBufferFree(buffer);
            return Err(LxmlError::Memory);
        }
        let len = usize::try_from(xmlBufferLength(buffer)).unwrap_or(0);
        let bytes = std::slice::from_raw_parts(content, len).to_vec();
        xmlBufferFree(buffer);
        Ok(bytes)
    }
}

/// An `xmlOutputBuffer` as lxml's `_tostring` makes one for `encoding=None` or `unicode`.
struct OutputBuffer(*mut xmlOutputBuffer);

impl Drop for OutputBuffer {
    fn drop(&mut self) {
        unsafe {
            xmlOutputBufferClose(self.0);
        }
    }
}

impl OutputBuffer {
    fn new() -> Result<OutputBuffer, LxmlError> {
        unsafe {
            let handler = xmlFindCharEncodingHandler(ptr::null());
            let buffer = xmlAllocOutputBuffer(handler);
            if buffer.is_null() {
                return Err(LxmlError::Memory);
            }
            Ok(OutputBuffer(buffer))
        }
    }

    /// `_writeNodeToBuffer` with `write_complete_document`, `with_tail`, the html method, no
    /// doctype argument and no pretty printing, for a root element.
    unsafe fn write_tree(self, doc: *mut xmlDoc, node: *mut xmlNode) -> Vec<u8> {
        unsafe {
            let buf = self.0;
            let subset = (*doc).intSubset;
            if !subset.is_null() {
                write_prev_siblings(buf, subset as *mut xmlNode);
            }
            write_dtd(buf, doc, (*node).name);
            write_prev_siblings(buf, node);
            htmlNodeDumpFormatOutput(buf, doc, node, ptr::null(), 0);
            // _writeTail
            let mut tail = (*node).next;
            while !tail.is_null() && matches!((*tail).type_, XML_TEXT_NODE | XML_CDATA_SECTION_NODE)
            {
                htmlNodeDumpFormatOutput(buf, (*tail).doc, tail, ptr::null(), 0);
                tail = (*tail).next;
            }
            write_next_siblings(buf, node);
            xmlOutputBufferFlush(buf);
            let content = xmlOutputBufferGetContent(buf);
            let size = xmlOutputBufferGetSize(buf);
            if content.is_null() {
                return Vec::new();
            }
            std::slice::from_raw_parts(content, size).to_vec()
        }
    }
}

unsafe fn is_element_like(node: *const xmlNode) -> bool {
    unsafe {
        matches!(
            (*node).type_,
            XML_ELEMENT_NODE | XML_COMMENT_NODE | XML_ENTITY_REF_NODE | XML_PI_NODE
        )
    }
}

/// `_writePrevSiblings`.
unsafe fn write_prev_siblings(buf: *mut xmlOutputBuffer, node: *mut xmlNode) {
    unsafe {
        if !(*node).parent.is_null() && is_element_like((*node).parent) {
            return;
        }
        let mut sibling = node;
        while !(*sibling).prev.is_null()
            && matches!((*(*sibling).prev).type_, XML_PI_NODE | XML_COMMENT_NODE)
        {
            sibling = (*sibling).prev;
        }
        while sibling != node {
            xmlNodeDumpOutput(buf, (*node).doc, sibling, 0, 0, ptr::null());
            sibling = (*sibling).next;
        }
    }
}

/// `_writeNextSiblings`.
unsafe fn write_next_siblings(buf: *mut xmlOutputBuffer, node: *mut xmlNode) {
    unsafe {
        if !(*node).parent.is_null() && is_element_like((*node).parent) {
            return;
        }
        let mut sibling = (*node).next;
        while !sibling.is_null() && matches!((*sibling).type_, XML_PI_NODE | XML_COMMENT_NODE) {
            xmlNodeDumpOutput(buf, (*node).doc, sibling, 0, 0, ptr::null());
            sibling = (*sibling).next;
        }
    }
}

unsafe fn write_str(buf: *mut xmlOutputBuffer, s: &[u8]) {
    unsafe {
        xmlOutputBufferWrite(
            buf,
            c_int::try_from(s.len()).unwrap_or(0),
            s.as_ptr() as *const c_char,
        );
    }
}

unsafe fn write_cstr(buf: *mut xmlOutputBuffer, s: *const xmlChar) {
    unsafe {
        xmlOutputBufferWriteString(buf, s as *const c_char);
    }
}

/// `_writeDtdToBuffer` for the html method.
unsafe fn write_dtd(buf: *mut xmlOutputBuffer, doc: *mut xmlDoc, root_name: *const xmlChar) {
    unsafe {
        let dtd = (*doc).intSubset;
        if dtd.is_null() || (*dtd).name.is_null() {
            return;
        }
        if xmlStrcasecmp(root_name, (*dtd).name) != 0 {
            return;
        }
        write_str(buf, b"<!DOCTYPE ");
        write_cstr(buf, (*dtd).name);
        let mut public_id = (*dtd).ExternalID;
        let mut sys_url = (*dtd).SystemID;
        if !public_id.is_null() && *public_id == 0 {
            public_id = ptr::null();
        }
        if !sys_url.is_null() && *sys_url == 0 {
            sys_url = ptr::null();
        }
        if !public_id.is_null() {
            write_str(buf, b" PUBLIC \"");
            write_cstr(buf, public_id);
            if !sys_url.is_null() {
                write_str(buf, b"\" ");
            } else {
                write_str(buf, b"\"");
            }
        } else if !sys_url.is_null() {
            write_str(buf, b" SYSTEM ");
        }
        if !sys_url.is_null() {
            let quote: &[u8] = if xmlStrchr(sys_url, b'"').is_null() {
                b"\""
            } else {
                b"'"
            };
            write_str(buf, quote);
            write_cstr(buf, sys_url);
            write_str(buf, quote);
        }
        if (*dtd).entities.is_null()
            && (*dtd).elements.is_null()
            && (*dtd).attributes.is_null()
            && (*dtd).notations.is_null()
            && (*dtd).pentities.is_null()
        {
            write_str(buf, b">\n");
            return;
        }
        write_str(buf, b" [\n");
        if !(*dtd).notations.is_null() {
            let table = xmlBufferCreate();
            if table.is_null() {
                return;
            }
            xmlDumpNotationTable(table, (*dtd).notations);
            xmlOutputBufferWrite(
                buf,
                xmlBufferLength(table),
                xmlBufferContent(table) as *const c_char,
            );
            xmlBufferFree(table);
        }
        let mut node = (*dtd).children;
        while !node.is_null() {
            xmlNodeDumpOutput(buf, (*node).doc, node, 0, 0, ptr::null());
            node = (*node).next;
        }
        write_str(buf, b"]>\n");
    }
}

/// `_textNodeOrSkip`.
unsafe fn text_node_or_skip(mut node: *mut xmlNode) -> *mut xmlNode {
    unsafe {
        while !node.is_null() {
            match (*node).type_ {
                XML_TEXT_NODE | XML_CDATA_SECTION_NODE => return node,
                XML_XINCLUDE_START | XML_XINCLUDE_END => node = (*node).next,
                _ => return ptr::null_mut(),
            }
        }
        ptr::null_mut()
    }
}

/// `_collectText`: the text of a run of text nodes, None if there are none.
unsafe fn collect_text(node: *mut xmlNode) -> Option<String> {
    unsafe {
        let mut node = text_node_or_skip(node);
        if node.is_null() {
            return None;
        }
        let mut text = Vec::new();
        while !node.is_null() {
            if !(*node).content.is_null() {
                text.extend_from_slice(CStr::from_ptr((*node).content as *const c_char).to_bytes());
            }
            node = text_node_or_skip((*node).next);
        }
        Some(String::from_utf8_lossy(&text).into_owned())
    }
}

/// `_removeText`.
unsafe fn remove_text(node: *mut xmlNode) {
    unsafe {
        let mut node = text_node_or_skip(node);
        while !node.is_null() {
            let next = text_node_or_skip((*node).next);
            xmlUnlinkNode(node);
            xmlFreeNode(node);
            node = next;
        }
    }
}

/// `xmlIsChar_ch`.
fn is_xml_char_ch(c: u8) -> bool {
    (0x9..=0xa).contains(&c) || c == 0xd || c >= 0x20
}

/// lxml's `_is_valid_xml_utf8`, byte for byte, including that it checks the last two bytes
/// only as ASCII.
fn is_valid_xml_utf8(s: &[u8]) -> bool {
    let end = s.len();
    let mut i = 0;
    let mut next3: u32 = 0;
    if end >= 3 {
        next3 = (u32::from(s[0]) << 8) | u32::from(s[1]);
    }
    while end >= 3 && i < end - 2 {
        next3 = 0x00ff_ffff & ((next3 << 8) | u32::from(s[i + 2]));
        if s[i] & 0x80 != 0 {
            if next3 == 0x00ef_bfbe || next3 == 0x00ef_bfbf {
                return false;
            }
            if (0x00ed_a080..=0x00ed_bfbf).contains(&next3) {
                return false;
            }
        } else if !is_xml_char_ch(s[i]) {
            return false;
        }
        i += 1;
    }
    while i < end {
        if s[i] & 0x80 == 0 && !is_xml_char_ch(s[i]) {
            return false;
        }
        i += 1;
    }
    true
}

const NOT_XML_COMPATIBLE: &str =
    "All strings must be XML compatible: Unicode or ASCII, no NULL bytes or control characters";

/// `_utf8(s)` for a str: its UTF-8 with a NUL on the end, or lxml's ValueError.
fn utf8(s: &str) -> Result<Vec<u8>, LxmlError> {
    if !is_valid_xml_utf8(s.as_bytes()) {
        return Err(LxmlError::Value(NOT_XML_COMPATIBLE));
    }
    let mut bytes = Vec::with_capacity(s.len() + 1);
    bytes.extend_from_slice(s.as_bytes());
    bytes.push(0);
    Ok(bytes)
}

/// `__getNsTag(tag, empty_ns=False)`: the namespace and the local name, each NUL-terminated.
fn ns_tag(tag: &str) -> Result<(Option<Vec<u8>>, Vec<u8>), LxmlError> {
    let bytes = utf8(tag)?;
    let tag = &bytes[..bytes.len() - 1];
    if let Some(rest) = tag.strip_prefix(b"{") {
        // strchr stops at the end of the string
        let Some(end) = rest.iter().position(|&b| b == b'}') else {
            return Err(LxmlError::Value("Invalid tag name"));
        };
        let local = &rest[end + 1..];
        if local.is_empty() {
            return Err(LxmlError::Value("Empty tag name"));
        }
        let ns = (end > 0).then(|| {
            let mut ns = rest[..end].to_vec();
            ns.push(0);
            ns
        });
        let mut local = local.to_vec();
        local.push(0);
        return Ok((ns, local));
    }
    if tag.is_empty() {
        return Err(LxmlError::Value("Empty tag name"));
    }
    Ok((None, bytes))
}

unsafe fn c_str<'s>(s: *const xmlChar) -> &'s str {
    if s.is_null() {
        return "";
    }
    let bytes = unsafe { CStr::from_ptr(s as *const c_char) }.to_bytes();
    std::str::from_utf8(bytes).unwrap_or("")
}

/// A string libxml2 allocated, as text, freed with `xmlFree`.
unsafe fn take_xml_string(s: *mut xmlChar) -> Option<String> {
    if s.is_null() {
        return None;
    }
    unsafe {
        let text =
            String::from_utf8_lossy(CStr::from_ptr(s as *const c_char).to_bytes()).into_owned();
        if let Some(free) = xmlFree {
            free(s as *mut c_void);
        }
        Some(text)
    }
}

/// What a node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Element,
    Comment,
    ProcessingInstruction,
    EntityRef,
    Other,
}

/// One of a document's element-like nodes: an element, a comment, a processing instruction or
/// an entity reference, as an lxml `_Element` proxy is.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    ptr: *mut xmlNode,
    doc: &'a Document,
    _not_send: PhantomData<*mut ()>,
}

impl PartialEq for Node<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl fmt::Debug for Node<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node({:?} {})", self.kind(), self.tag().unwrap_or(""))
    }
}

impl<'a> Node<'a> {
    fn wrap(ptr: *mut xmlNode, doc: &'a Document) -> Option<Node<'a>> {
        (!ptr.is_null()).then_some(Node {
            ptr,
            doc,
            _not_send: PhantomData,
        })
    }

    pub fn kind(&self) -> Kind {
        match unsafe { (*self.ptr).type_ } {
            XML_ELEMENT_NODE => Kind::Element,
            XML_COMMENT_NODE => Kind::Comment,
            XML_PI_NODE => Kind::ProcessingInstruction,
            XML_ENTITY_REF_NODE => Kind::EntityRef,
            _ => Kind::Other,
        }
    }

    /// An element's name (libxml2's HTML parser lowercases it), None for anything else.
    pub fn tag(&self) -> Option<&'a str> {
        (self.kind() == Kind::Element).then(|| unsafe { c_str((*self.ptr).name) })
    }

    /// `getparent()`: the parent element, None for the root.
    pub fn getparent(&self) -> Option<Node<'a>> {
        unsafe {
            if !is_element_like(self.ptr) {
                return None;
            }
            let parent = (*self.ptr).parent;
            if parent.is_null() || !is_element_like(parent) {
                return None;
            }
            Node::wrap(parent, self.doc)
        }
    }

    /// `getprevious()`.
    pub fn getprevious(&self) -> Option<Node<'a>> {
        unsafe {
            let mut node = (*self.ptr).prev;
            while !node.is_null() {
                if is_element_like(node) {
                    return Node::wrap(node, self.doc);
                }
                node = (*node).prev;
            }
            None
        }
    }

    /// `itersiblings()`, collected: the following element-like siblings.
    pub fn following_siblings(&self) -> Vec<Node<'a>> {
        let mut siblings = Vec::new();
        unsafe {
            let mut node = (*self.ptr).next;
            while !node.is_null() {
                if is_element_like(node) {
                    siblings.push(Node {
                        ptr: node,
                        doc: self.doc,
                        _not_send: PhantomData,
                    });
                }
                node = (*node).next;
            }
        }
        siblings
    }

    /// `.text`.
    pub fn text(&self) -> Option<String> {
        unsafe { collect_text((*self.ptr).children) }
    }

    /// `.tail`.
    pub fn tail(&self) -> Option<String> {
        unsafe { collect_text((*self.ptr).next) }
    }

    /// `.text = value`, `_setNodeText`.
    pub fn set_text(&self, value: Option<&str>) -> Result<(), LxmlError> {
        unsafe {
            remove_text((*self.ptr).children);
            let Some(value) = value else {
                return Ok(());
            };
            let text = utf8(value)?;
            let node = xmlNewDocText((*self.ptr).doc, text.as_ptr());
            if node.is_null() {
                return Err(LxmlError::Memory);
            }
            if (*self.ptr).children.is_null() {
                xmlAddChild(self.ptr, node);
            } else {
                xmlAddPrevSibling((*self.ptr).children, node);
            }
        }
        Ok(())
    }

    /// `.tail = value`, `_setTailText`.
    pub fn set_tail(&self, value: Option<&str>) -> Result<(), LxmlError> {
        unsafe {
            remove_text((*self.ptr).next);
            let Some(value) = value else {
                return Ok(());
            };
            let text = utf8(value)?;
            let node = xmlNewDocText((*self.ptr).doc, text.as_ptr());
            if node.is_null() {
                return Err(LxmlError::Memory);
            }
            xmlAddNextSibling(self.ptr, node);
        }
        Ok(())
    }

    fn attributes(&self) -> Vec<*mut xmlAttr> {
        let mut attrs = Vec::new();
        if self.kind() != Kind::Element {
            return attrs;
        }
        unsafe {
            let mut attr = (*self.ptr).properties;
            while !attr.is_null() {
                if (*attr).type_ == XML_ATTRIBUTE_NODE {
                    attrs.push(attr);
                }
                attr = (*attr).next;
            }
        }
        attrs
    }

    fn attribute_value(&self, attr: *mut xmlAttr) -> String {
        unsafe {
            let ns = if (*attr).ns.is_null() {
                ptr::null()
            } else {
                (*(*attr).ns).href
            };
            take_xml_string(xmlGetNsProp(self.ptr, (*attr).name, ns)).unwrap_or_default()
        }
    }

    fn attribute_key(attr: *mut xmlAttr) -> String {
        unsafe {
            let name = c_str((*attr).name);
            if (*attr).ns.is_null() || (*(*attr).ns).href.is_null() {
                name.to_owned()
            } else {
                format!("{{{}}}{name}", c_str((*(*attr).ns).href))
            }
        }
    }

    /// `list(attrib)`: the attributes' names, `{ns}name` for one in a namespace.
    pub fn keys(&self) -> Vec<String> {
        self.attributes()
            .into_iter()
            .map(Node::attribute_key)
            .collect()
    }

    /// `attrib.values()`.
    pub fn values(&self) -> Vec<String> {
        self.attributes()
            .into_iter()
            .map(|attr| self.attribute_value(attr))
            .collect()
    }

    /// `items()`.
    pub fn items(&self) -> Vec<(String, String)> {
        self.attributes()
            .into_iter()
            .map(|attr| (Node::attribute_key(attr), self.attribute_value(attr)))
            .collect()
    }

    /// `get(key)`, for a key with no namespace, as the ported code asks.
    pub fn get(&self, key: &str) -> Option<String> {
        if self.kind() != Kind::Element {
            return None;
        }
        let mut name = key.as_bytes().to_vec();
        if name.contains(&0) {
            return None;
        }
        name.push(0);
        unsafe { take_xml_string(xmlGetNsProp(self.ptr, name.as_ptr(), ptr::null())) }
    }

    /// `attrib[key] = value`, `_setAttributeValue` for an HTML document: no check of the name
    /// beyond `_getNsTag`'s, and a `{ns}name` key sets the attribute in that namespace.
    pub fn set(&self, key: &str, value: &str) -> Result<(), LxmlError> {
        if self.kind() != Kind::Element {
            // a comment's attrib is an immutable empty mapping
            return Err(LxmlError::Value("immutable"));
        }
        let (ns, tag) = ns_tag(key)?;
        let value = utf8(value)?;
        unsafe {
            let c_ns = match ns {
                None => ptr::null_mut(),
                Some(href) => self.find_or_build_ns(&href)?,
            };
            xmlSetNsProp(self.ptr, c_ns, tag.as_ptr(), value.as_ptr());
        }
        Ok(())
    }

    /// `_Document._findOrBuildNodeNs(c_node, href, NULL, is_attribute=1)`: a prefixed
    /// declaration of that URI in scope, or a new one on the element, its prefix from lxml's
    /// table of well-known namespaces or the document's next free `ns<n>`. An HTML document
    /// declares no namespaces of its own, so the declarations found are ones this made.
    unsafe fn find_or_build_ns(&self, href: &[u8]) -> Result<*mut xmlNs, LxmlError> {
        unsafe {
            let doc = (*self.ptr).doc;
            let uri = &href[..href.len() - 1];
            if uri == b"http://www.w3.org/XML/1998/namespace" {
                let found = xmlSearchNsByHref(doc, self.ptr, href.as_ptr());
                if !found.is_null() {
                    return Ok(found);
                }
            } else {
                let mut node = self.ptr;
                while !node.is_null() && (*node).type_ == XML_ELEMENT_NODE {
                    let mut ns = (*node).nsDef;
                    while !ns.is_null() {
                        if !(*ns).href.is_null()
                            && !(*ns).prefix.is_null()
                            && CStr::from_ptr((*ns).href as *const c_char).to_bytes() == uri
                            && xmlSearchNs(doc, self.ptr, (*ns).prefix) == ns
                        {
                            return Ok(ns);
                        }
                        ns = (*ns).next;
                    }
                    node = (*node).parent;
                }
            }
            let mut prefix = match DEFAULT_PREFIXES
                .iter()
                .find(|(known, _)| known.as_bytes() == uri)
            {
                Some((_, prefix)) => format!("{prefix}\0"),
                None => self.doc.new_prefix(),
            };
            while !xmlSearchNs(doc, self.ptr, prefix.as_ptr()).is_null() {
                prefix = self.doc.new_prefix();
            }
            let ns = xmlNewNs(self.ptr, href.as_ptr(), prefix.as_ptr());
            if ns.is_null() {
                return Err(LxmlError::Memory);
            }
            Ok(ns)
        }
    }

    /// `parent.remove(child)`: the child goes with its tail, and stays alive, detached.
    pub fn remove(&self, child: Node<'a>) -> Result<(), LxmlError> {
        unsafe {
            if (*child.ptr).parent != self.ptr {
                return Err(LxmlError::Value("Element is not a child of this node."));
            }
            let next = (*child.ptr).next;
            xmlUnlinkNode(child.ptr);
            move_tail(next, child.ptr);
        }
        self.doc.detached.borrow_mut().push(child.ptr);
        Ok(())
    }

    /// `append(child)`, for a child in the same document: it moves with its tail.
    pub fn append(&self, child: Node<'a>) {
        unsafe {
            let next = (*child.ptr).next;
            xmlUnlinkNode(child.ptr);
            // _linkChild, which doesn't merge text as xmlAddChild would
            (*child.ptr).parent = self.ptr;
            if (*self.ptr).children.is_null() {
                (*self.ptr).children = child.ptr;
                (*self.ptr).last = child.ptr;
            } else {
                (*child.ptr).prev = (*self.ptr).last;
                (*(*self.ptr).last).next = child.ptr;
                (*self.ptr).last = child.ptr;
            }
            move_tail(next, child.ptr);
        }
    }

    /// `iter()`: the node and everything element-like below it, in document order. The next node
    /// is found when this one is returned, as lxml's iterator does, which decides what happens
    /// when the caller changes the tree on the way.
    pub fn iter(&self) -> DepthFirst<'a> {
        DepthFirst::new(*self, Matcher::Any, true)
    }

    /// `iterdescendants(tag)`: below the node only. `"*"` is any element, a name an element of
    /// that name in no namespace.
    pub fn iterdescendants(&self, tag: &str) -> DepthFirst<'a> {
        let matcher = if tag == "*" {
            Matcher::AnyElement
        } else {
            Matcher::Name(tag.to_owned())
        };
        DepthFirst::new(*self, matcher, false)
    }
}

/// `_moveTail(c_tail, c_target)`: the text nodes from `tail` on move to follow `target`.
unsafe fn move_tail(tail: *mut xmlNode, mut target: *mut xmlNode) {
    unsafe {
        let mut tail = text_node_or_skip(tail);
        while !tail.is_null() {
            let next = text_node_or_skip((*tail).next);
            target = xmlAddNextSibling(target, tail);
            tail = next;
        }
    }
}

enum Matcher {
    /// No tag: elements, comments, processing instructions and entity references.
    Any,
    AnyElement,
    Name(String),
}

impl Matcher {
    unsafe fn matches(&self, node: *mut xmlNode) -> bool {
        unsafe {
            match self {
                Matcher::Any => is_element_like(node),
                Matcher::AnyElement => (*node).type_ == XML_ELEMENT_NODE,
                Matcher::Name(name) => {
                    (*node).type_ == XML_ELEMENT_NODE
                        && ((*node).ns.is_null() || (*(*node).ns).href.is_null())
                        && c_str((*node).name) == name
                }
            }
        }
    }
}

/// lxml's `ElementDepthFirstIterator`.
pub struct DepthFirst<'a> {
    top: *mut xmlNode,
    next: *mut xmlNode,
    matcher: Matcher,
    doc: &'a Document,
}

impl<'a> DepthFirst<'a> {
    fn new(node: Node<'a>, matcher: Matcher, inclusive: bool) -> DepthFirst<'a> {
        let mut iter = DepthFirst {
            top: node.ptr,
            next: node.ptr,
            matcher,
            doc: node.doc,
        };
        if !inclusive || !unsafe { iter.matcher.matches(node.ptr) } {
            iter.advance();
        }
        iter
    }

    /// `_nextNodeMatchTag` from `next`: `BEGIN_FOR_EACH_ELEMENT_FROM(top, node, 0)`.
    fn advance(&mut self) {
        unsafe {
            let mut node = self.next;
            if node.is_null() {
                return;
            }
            if !is_element_like(node) {
                node = if node == self.top {
                    ptr::null_mut()
                } else {
                    advance_to_element((*node).next)
                };
            } else {
                node = traverse_to_next(self.top, node);
            }
            while !node.is_null() {
                if self.matcher.matches(node) {
                    break;
                }
                node = traverse_to_next(self.top, node);
            }
            self.next = node;
        }
    }
}

impl<'a> Iterator for DepthFirst<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        let current = Node::wrap(self.next, self.doc)?;
        self.advance();
        Some(current)
    }
}

/// `_LX__ADVANCE_TO_NEXT` with only_elements.
unsafe fn advance_to_element(mut node: *mut xmlNode) -> *mut xmlNode {
    unsafe {
        while !node.is_null() && !is_element_like(node) {
            node = (*node).next;
        }
        node
    }
}

/// `_LX__TRAVERSE_TO_NEXT(stop, node, only_elements=1)`.
unsafe fn traverse_to_next(stop: *mut xmlNode, mut node: *mut xmlNode) -> *mut xmlNode {
    unsafe {
        let mut next = (*node).children;
        if !next.is_null() {
            if matches!((*node).type_, XML_ENTITY_REF_NODE | XML_DTD_NODE) {
                next = ptr::null_mut();
            } else {
                next = advance_to_element(next);
            }
        }
        if next.is_null() && node != stop {
            next = advance_to_element((*node).next);
            while next.is_null() {
                node = (*node).parent;
                if node.is_null() || node == stop || !is_element_like(node) {
                    break;
                }
                next = advance_to_element((*node).next);
            }
        }
        next
    }
}

#[cfg(test)]
mod tests;
