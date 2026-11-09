//! The parts of libxml2 2.14.6's C API this crate calls, declared by hand from
//! `vendor/libxml2/include/libxml/`. The structs are the public ones of `tree.h`, field for
//! field, which libxml2 keeps stable.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::{c_char, c_int, c_uint, c_ushort, c_void};

pub type xmlChar = u8;

pub const XML_ELEMENT_NODE: c_int = 1;
pub const XML_ATTRIBUTE_NODE: c_int = 2;
pub const XML_TEXT_NODE: c_int = 3;
pub const XML_CDATA_SECTION_NODE: c_int = 4;
pub const XML_ENTITY_REF_NODE: c_int = 5;
pub const XML_PI_NODE: c_int = 7;
pub const XML_COMMENT_NODE: c_int = 8;
pub const XML_DOCUMENT_NODE: c_int = 9;
pub const XML_HTML_DOCUMENT_NODE: c_int = 13;
pub const XML_DTD_NODE: c_int = 14;
pub const XML_XINCLUDE_START: c_int = 19;
pub const XML_XINCLUDE_END: c_int = 20;

pub const HTML_PARSE_RECOVER: c_int = 1 << 0;
pub const HTML_PARSE_NODEFDTD: c_int = 1 << 2;
pub const HTML_PARSE_NOERROR: c_int = 1 << 5;
pub const HTML_PARSE_NOWARNING: c_int = 1 << 6;
pub const HTML_PARSE_NONET: c_int = 1 << 11;
pub const HTML_PARSE_COMPACT: c_int = 1 << 16;

#[repr(C)]
pub struct xmlNode {
    pub _private: *mut c_void,
    pub type_: c_int,
    pub name: *const xmlChar,
    pub children: *mut xmlNode,
    pub last: *mut xmlNode,
    pub parent: *mut xmlNode,
    pub next: *mut xmlNode,
    pub prev: *mut xmlNode,
    pub doc: *mut xmlDoc,
    pub ns: *mut xmlNs,
    pub content: *mut xmlChar,
    pub properties: *mut xmlAttr,
    pub nsDef: *mut xmlNs,
    pub psvi: *mut c_void,
    pub line: c_ushort,
    pub extra: c_ushort,
}

#[repr(C)]
pub struct xmlAttr {
    pub _private: *mut c_void,
    pub type_: c_int,
    pub name: *const xmlChar,
    pub children: *mut xmlNode,
    pub last: *mut xmlNode,
    pub parent: *mut xmlNode,
    pub next: *mut xmlAttr,
    pub prev: *mut xmlAttr,
    pub doc: *mut xmlDoc,
    pub ns: *mut xmlNs,
    pub atype: c_int,
    pub psvi: *mut c_void,
    pub id: *mut c_void,
}

#[repr(C)]
pub struct xmlNs {
    pub next: *mut xmlNs,
    pub type_: c_int,
    pub href: *const xmlChar,
    pub prefix: *const xmlChar,
    pub _private: *mut c_void,
    pub context: *mut xmlDoc,
}

#[repr(C)]
pub struct xmlDtd {
    pub _private: *mut c_void,
    pub type_: c_int,
    pub name: *const xmlChar,
    pub children: *mut xmlNode,
    pub last: *mut xmlNode,
    pub parent: *mut xmlDoc,
    pub next: *mut xmlNode,
    pub prev: *mut xmlNode,
    pub doc: *mut xmlDoc,
    pub notations: *mut c_void,
    pub elements: *mut c_void,
    pub attributes: *mut c_void,
    pub entities: *mut c_void,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub pentities: *mut c_void,
}

#[repr(C)]
pub struct xmlDoc {
    pub _private: *mut c_void,
    pub type_: c_int,
    pub name: *mut c_char,
    pub children: *mut xmlNode,
    pub last: *mut xmlNode,
    pub parent: *mut xmlNode,
    pub next: *mut xmlNode,
    pub prev: *mut xmlNode,
    pub doc: *mut xmlDoc,
    pub compression: c_int,
    pub standalone: c_int,
    pub intSubset: *mut xmlDtd,
    pub extSubset: *mut xmlDtd,
    pub oldNs: *mut xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut c_void,
    pub refs: *mut c_void,
    pub URL: *const xmlChar,
    pub charset: c_int,
    pub dict: *mut c_void,
    pub psvi: *mut c_void,
    pub parseFlags: c_int,
    pub properties: c_int,
}

/// Opaque: only passed back to libxml2.
#[repr(C)]
pub struct xmlParserCtxt {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct xmlBuffer {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct xmlOutputBuffer {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct xmlCharEncodingHandler {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct xmlError {
    _opaque: [u8; 0],
}

pub type xmlStructuredErrorFunc = Option<unsafe extern "C" fn(*mut c_void, *const xmlError)>;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut c_void)>;

/// The SAX callbacks of `parser.h`'s `xmlSAXHandler`, in its order. Only the HTML parser's
/// ones are given a type; the others stay pointers.
#[repr(C)]
pub struct xmlSAXHandler {
    pub internalSubset:
        Option<unsafe extern "C" fn(*mut c_void, *const xmlChar, *const xmlChar, *const xmlChar)>,
    pub isStandalone: *mut c_void,
    pub hasInternalSubset: *mut c_void,
    pub hasExternalSubset: *mut c_void,
    pub resolveEntity: *mut c_void,
    pub getEntity: *mut c_void,
    pub entityDecl: *mut c_void,
    pub notationDecl: *mut c_void,
    pub attributeDecl: *mut c_void,
    pub elementDecl: *mut c_void,
    pub unparsedEntityDecl: *mut c_void,
    pub setDocumentLocator: *mut c_void,
    pub startDocument: Option<unsafe extern "C" fn(*mut c_void)>,
    pub endDocument: Option<unsafe extern "C" fn(*mut c_void)>,
    pub startElement:
        Option<unsafe extern "C" fn(*mut c_void, *const xmlChar, *mut *const xmlChar)>,
    pub endElement: Option<unsafe extern "C" fn(*mut c_void, *const xmlChar)>,
    pub reference: *mut c_void,
    pub characters: Option<unsafe extern "C" fn(*mut c_void, *const xmlChar, c_int)>,
    pub ignorableWhitespace: Option<unsafe extern "C" fn(*mut c_void, *const xmlChar, c_int)>,
    pub processingInstruction:
        Option<unsafe extern "C" fn(*mut c_void, *const xmlChar, *const xmlChar)>,
    pub comment: Option<unsafe extern "C" fn(*mut c_void, *const xmlChar)>,
    pub warning: *mut c_void,
    pub error: *mut c_void,
    pub fatalError: *mut c_void,
    pub getParameterEntity: *mut c_void,
    pub cdataBlock: Option<unsafe extern "C" fn(*mut c_void, *const xmlChar, c_int)>,
    pub externalSubset: *mut c_void,
    pub initialized: c_uint,
    pub _private: *mut c_void,
    pub startElementNs: *mut c_void,
    pub endElementNs: *mut c_void,
    pub serror: xmlStructuredErrorFunc,
}

unsafe extern "C" {
    pub static xmlFree: xmlFreeFunc;

    pub fn xmlInitParser();
    pub fn htmlNewParserCtxt() -> *mut xmlParserCtxt;
    pub fn htmlNewSAXParserCtxt(
        sax: *const xmlSAXHandler,
        user_data: *mut c_void,
    ) -> *mut xmlParserCtxt;
    pub fn htmlFreeParserCtxt(ctxt: *mut xmlParserCtxt);
    pub fn htmlCtxtReadMemory(
        ctxt: *mut xmlParserCtxt,
        buffer: *const c_char,
        size: c_int,
        url: *const c_char,
        encoding: *const c_char,
        options: c_int,
    ) -> *mut xmlDoc;
    pub fn htmlCtxtUseOptions(ctxt: *mut xmlParserCtxt, options: c_int) -> c_int;
    pub fn htmlCtxtReset(ctxt: *mut xmlParserCtxt);
    pub fn htmlParseChunk(
        ctxt: *mut xmlParserCtxt,
        chunk: *const c_char,
        size: c_int,
        terminate: c_int,
    ) -> c_int;
    pub fn htmlCreatePushParserCtxt(
        sax: *const xmlSAXHandler,
        user_data: *mut c_void,
        chunk: *const c_char,
        size: c_int,
        filename: *const c_char,
        enc: c_int,
    ) -> *mut xmlParserCtxt;
    pub fn xmlCtxtSetErrorHandler(
        ctxt: *mut xmlParserCtxt,
        handler: xmlStructuredErrorFunc,
        data: *mut c_void,
    );
    pub fn xmlSwitchEncodingName(ctxt: *mut xmlParserCtxt, encoding: *const c_char) -> c_int;
    pub fn xmlFreeDoc(doc: *mut xmlDoc);
    pub fn xmlDocGetRootElement(doc: *const xmlDoc) -> *mut xmlNode;

    pub fn xmlGetNsProp(
        node: *const xmlNode,
        name: *const xmlChar,
        ns: *const xmlChar,
    ) -> *mut xmlChar;
    pub fn xmlSetNsProp(
        node: *mut xmlNode,
        ns: *mut xmlNs,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> *mut xmlAttr;
    pub fn xmlSearchNsByHref(
        doc: *mut xmlDoc,
        node: *mut xmlNode,
        href: *const xmlChar,
    ) -> *mut xmlNs;
    pub fn xmlSearchNs(doc: *mut xmlDoc, node: *mut xmlNode, prefix: *const xmlChar) -> *mut xmlNs;
    pub fn xmlNewNs(node: *mut xmlNode, href: *const xmlChar, prefix: *const xmlChar)
    -> *mut xmlNs;

    pub fn xmlUnlinkNode(node: *mut xmlNode);
    pub fn xmlFreeNode(node: *mut xmlNode);
    pub fn xmlAddChild(parent: *mut xmlNode, cur: *mut xmlNode) -> *mut xmlNode;
    pub fn xmlAddNextSibling(cur: *mut xmlNode, elem: *mut xmlNode) -> *mut xmlNode;
    pub fn xmlAddPrevSibling(cur: *mut xmlNode, elem: *mut xmlNode) -> *mut xmlNode;
    pub fn xmlNewDocText(doc: *const xmlDoc, content: *const xmlChar) -> *mut xmlNode;

    pub fn xmlBufferCreate() -> *mut xmlBuffer;
    pub fn xmlBufferFree(buf: *mut xmlBuffer);
    pub fn xmlBufferContent(buf: *const xmlBuffer) -> *const xmlChar;
    pub fn xmlBufferLength(buf: *const xmlBuffer) -> c_int;
    pub fn xmlBufferWriteChar(buf: *mut xmlBuffer, string: *const c_char);
    pub fn xmlNodeBufGetContent(buf: *mut xmlBuffer, cur: *const xmlNode) -> c_int;

    pub fn xmlFindCharEncodingHandler(name: *const c_char) -> *mut xmlCharEncodingHandler;
    pub fn xmlAllocOutputBuffer(encoder: *mut xmlCharEncodingHandler) -> *mut xmlOutputBuffer;
    pub fn xmlOutputBufferFlush(out: *mut xmlOutputBuffer) -> c_int;
    pub fn xmlOutputBufferClose(out: *mut xmlOutputBuffer) -> c_int;
    pub fn xmlOutputBufferGetContent(out: *mut xmlOutputBuffer) -> *const xmlChar;
    pub fn xmlOutputBufferGetSize(out: *mut xmlOutputBuffer) -> usize;
    pub fn xmlOutputBufferWrite(out: *mut xmlOutputBuffer, len: c_int, buf: *const c_char)
    -> c_int;
    pub fn xmlOutputBufferWriteString(out: *mut xmlOutputBuffer, s: *const c_char) -> c_int;
    pub fn htmlNodeDumpFormatOutput(
        buf: *mut xmlOutputBuffer,
        doc: *mut xmlDoc,
        cur: *mut xmlNode,
        encoding: *const c_char,
        format: c_int,
    );
    pub fn xmlNodeDumpOutput(
        buf: *mut xmlOutputBuffer,
        doc: *mut xmlDoc,
        cur: *mut xmlNode,
        level: c_int,
        format: c_int,
        encoding: *const c_char,
    );
    pub fn xmlStrcasecmp(a: *const xmlChar, b: *const xmlChar) -> c_int;
    pub fn xmlStrchr(s: *const xmlChar, c: xmlChar) -> *const xmlChar;
    pub fn xmlDumpNotationTable(buf: *mut xmlBuffer, table: *mut c_void);
}
