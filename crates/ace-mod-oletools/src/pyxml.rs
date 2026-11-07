//! `xml.etree.ElementTree.fromstring(bytes)` of Python 3.14: a port of expat 2.9.0's tokenizer, prolog
//! roles and parser in namespace mode, with `_elementtree`'s handlers and pyexpat's unknown-encoding
//! handler on top, so that errors come with Python's kinds, messages and positions.
//!
//! Python feeds the whole buffer with `isFinal` false and then an empty final one. Both passes reach
//! the same tokens as one final pass does, so this runs one.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use crate::codepage::Decoder;
use crate::py::{PyErr, PyResult, memory_error};

/// `Element`, with `text` the text before the first child.
#[derive(Default)]
pub struct Element {
    pub tag: String,
    /// The tag's namespace prefix as written, which ElementTree drops and minidom's names keep.
    pub prefix: Option<String>,
    pub attrib: Vec<(String, String)>,
    pub text: Option<String>,
    pub children: Vec<Element>,
}

impl Element {
    /// `Element.get(key)`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attrib
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// `Element.iter(tag)`: document order, self included, and `*` matches everything.
    pub fn iter_tag<'a>(&'a self, tag: &str) -> Vec<&'a Element> {
        let mut found = Vec::new();
        let mut stack = vec![self];
        while let Some(element) = stack.pop() {
            if tag == "*" || element.tag == tag {
                found.push(element);
            }
            stack.extend(element.children.iter().rev());
        }
        found
    }

    /// `Element.iterfind(tag)` of a plain tag: the direct children.
    pub fn find_children<'a>(&'a self, tag: &str) -> Vec<&'a Element> {
        self.children
            .iter()
            .filter(|child| tag == "*" || child.tag == tag)
            .collect()
    }

    fn shallow(&self) -> Element {
        Element {
            tag: self.tag.clone(),
            prefix: self.prefix.clone(),
            attrib: self.attrib.clone(),
            text: self.text.clone(),
            children: Vec::with_capacity(self.children.len()),
        }
    }
}

// A deep tree must not take the stack with it, so these three don't recurse.
impl Drop for Element {
    fn drop(&mut self) {
        if self.children.is_empty() {
            return;
        }
        let mut stack = std::mem::take(&mut self.children);
        while let Some(mut element) = stack.pop() {
            stack.append(&mut element.children);
        }
    }
}

impl Clone for Element {
    fn clone(&self) -> Element {
        let mut frames = vec![(self, self.shallow(), 0)];
        loop {
            let Some(frame) = frames.last_mut() else {
                return Element::default();
            };
            if let Some(child) = frame.0.children.get(frame.2) {
                frame.2 += 1;
                frames.push((child, child.shallow(), 0));
                continue;
            }
            let Some((_, done, _)) = frames.pop() else {
                return Element::default();
            };
            match frames.last_mut() {
                Some(parent) => parent.1.children.push(done),
                None => return done,
            }
        }
    }
}

impl fmt::Debug for Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut stack = vec![(self, 0)];
        while let Some((element, at)) = stack.pop() {
            if at == 0 {
                write!(
                    f,
                    "Element {{ tag: {:?}, attrib: {:?}, text: {:?}, children: [",
                    element.tag, element.attrib, element.text
                )?;
            }
            if let Some(child) = element.children.get(at) {
                if at > 0 {
                    f.write_str(", ")?;
                }
                stack.push((element, at + 1));
                stack.push((child, 0));
            } else {
                f.write_str("] }")?;
            }
        }
        Ok(())
    }
}

/// `xml.etree.ElementTree.fromstring(data)`.
pub fn fromstring(data: &[u8]) -> PyResult<Element> {
    if data.len() > i32::MAX as usize {
        return Err(PyErr::new("OverflowError", "size does not fit in an int"));
    }
    Parser::new(data).parse()
}

/// What expat's error code says, for `XML_ErrorString`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmlError {
    NoMemory,
    Syntax,
    NoElements,
    InvalidToken,
    UnclosedToken,
    PartialChar,
    TagMismatch,
    DuplicateAttribute,
    JunkAfterDocElement,
    ParamEntityRef,
    UndefinedEntity,
    RecursiveEntityRef,
    AsyncEntity,
    BadCharRef,
    BinaryEntityRef,
    AttributeExternalEntityRef,
    MisplacedXmlPi,
    UnknownEncoding,
    IncorrectEncoding,
    UnclosedCdataSection,
    UnboundPrefix,
    UndeclaringPrefix,
    XmlDecl,
    PublicId,
    ReservedPrefixXml,
    ReservedPrefixXmlns,
    ReservedNamespaceUri,
    AmplificationLimitBreach,
}

impl XmlError {
    fn message(self) -> &'static str {
        match self {
            XmlError::NoMemory => "out of memory",
            XmlError::Syntax => "syntax error",
            XmlError::NoElements => "no element found",
            XmlError::InvalidToken => "not well-formed (invalid token)",
            XmlError::UnclosedToken => "unclosed token",
            XmlError::PartialChar => "partial character",
            XmlError::TagMismatch => "mismatched tag",
            XmlError::DuplicateAttribute => "duplicate attribute",
            XmlError::JunkAfterDocElement => "junk after document element",
            XmlError::ParamEntityRef => "illegal parameter entity reference",
            XmlError::UndefinedEntity => "undefined entity",
            XmlError::RecursiveEntityRef => "recursive entity reference",
            XmlError::AsyncEntity => "asynchronous entity",
            XmlError::BadCharRef => "reference to invalid character number",
            XmlError::BinaryEntityRef => "reference to binary entity",
            XmlError::AttributeExternalEntityRef => "reference to external entity in attribute",
            XmlError::MisplacedXmlPi => "XML or text declaration not at start of entity",
            XmlError::UnknownEncoding => "unknown encoding",
            XmlError::IncorrectEncoding => "encoding specified in XML declaration is incorrect",
            XmlError::UnclosedCdataSection => "unclosed CDATA section",
            XmlError::UnboundPrefix => "unbound prefix",
            XmlError::UndeclaringPrefix => "must not undeclare prefix",
            XmlError::XmlDecl => "XML declaration not well-formed",
            XmlError::PublicId => "illegal character(s) in public id",
            XmlError::ReservedPrefixXml => {
                "reserved prefix (xml) must not be undeclared or bound to another namespace name"
            }
            XmlError::ReservedPrefixXmlns => {
                "reserved prefix (xmlns) must not be declared or undeclared"
            }
            XmlError::ReservedNamespaceUri => {
                "prefix must not be bound to one of the reserved namespace names"
            }
            XmlError::AmplificationLimitBreach => {
                "limit on input amplification factor (from DTD and entities) breached"
            }
        }
    }
}

/// Why parsing stopped: an expat error, reported with the position, or an exception from a handler.
#[derive(Debug)]
enum Stop {
    Xml(XmlError),
    Py(PyErr),
}

impl From<XmlError> for Stop {
    fn from(error: XmlError) -> Stop {
        Stop::Xml(error)
    }
}

const BT_NONXML: u8 = 0;
const BT_MALFORM: u8 = 1;
const BT_LT: u8 = 2;
const BT_AMP: u8 = 3;
const BT_RSQB: u8 = 4;
const BT_LEAD2: u8 = 5;
const BT_LEAD3: u8 = 6;
const BT_LEAD4: u8 = 7;
const BT_TRAIL: u8 = 8;
const BT_CR: u8 = 9;
const BT_LF: u8 = 10;
const BT_GT: u8 = 11;
const BT_QUOT: u8 = 12;
const BT_APOS: u8 = 13;
const BT_EQUALS: u8 = 14;
const BT_QUEST: u8 = 15;
const BT_EXCL: u8 = 16;
const BT_SOL: u8 = 17;
const BT_SEMI: u8 = 18;
const BT_NUM: u8 = 19;
const BT_LSQB: u8 = 20;
const BT_S: u8 = 21;
const BT_NMSTRT: u8 = 22;
const BT_COLON: u8 = 23;
const BT_HEX: u8 = 24;
const BT_DIGIT: u8 = 25;
const BT_NAME: u8 = 26;
const BT_MINUS: u8 = 27;
const BT_OTHER: u8 = 28;
const BT_NONASCII: u8 = 29;
const BT_PERCNT: u8 = 30;
const BT_LPAR: u8 = 31;
const BT_RPAR: u8 = 32;
const BT_AST: u8 = 33;
const BT_PLUS: u8 = 34;
const BT_COMMA: u8 = 35;
const BT_VERBAR: u8 = 36;

const ASCII_TAB: [u8; 128] = [
    BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML,
    BT_NONXML, BT_S, BT_LF, BT_NONXML, BT_NONXML, BT_CR, BT_NONXML, BT_NONXML, BT_NONXML,
    BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML,
    BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_S, BT_EXCL,
    BT_QUOT, BT_NUM, BT_OTHER, BT_PERCNT, BT_AMP, BT_APOS, BT_LPAR, BT_RPAR, BT_AST, BT_PLUS,
    BT_COMMA, BT_MINUS, BT_NAME, BT_SOL, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT,
    BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_COLON, BT_SEMI, BT_LT, BT_EQUALS, BT_GT,
    BT_QUEST, BT_OTHER, BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_LSQB, BT_OTHER, BT_RSQB, BT_OTHER, BT_NMSTRT, BT_OTHER, BT_HEX,
    BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_OTHER,
    BT_VERBAR, BT_OTHER, BT_OTHER, BT_OTHER,
];
const IASCII_TAB: [u8; 128] = [
    BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML,
    BT_NONXML, BT_S, BT_LF, BT_NONXML, BT_NONXML, BT_S, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML,
    BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML,
    BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_S, BT_EXCL, BT_QUOT,
    BT_NUM, BT_OTHER, BT_PERCNT, BT_AMP, BT_APOS, BT_LPAR, BT_RPAR, BT_AST, BT_PLUS, BT_COMMA,
    BT_MINUS, BT_NAME, BT_SOL, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT,
    BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_DIGIT, BT_COLON, BT_SEMI, BT_LT, BT_EQUALS, BT_GT, BT_QUEST,
    BT_OTHER, BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_HEX, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_LSQB, BT_OTHER, BT_RSQB, BT_OTHER, BT_NMSTRT, BT_OTHER, BT_HEX, BT_HEX, BT_HEX,
    BT_HEX, BT_HEX, BT_HEX, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_OTHER, BT_VERBAR,
    BT_OTHER, BT_OTHER, BT_OTHER,
];
const LATIN1_TAB: [u8; 128] = [
    BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER,
    BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER,
    BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER,
    BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER,
    BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_NMSTRT, BT_OTHER, BT_OTHER,
    BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER, BT_NMSTRT,
    BT_OTHER, BT_NAME, BT_OTHER, BT_OTHER, BT_NMSTRT, BT_OTHER, BT_OTHER, BT_OTHER, BT_OTHER,
    BT_OTHER, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_OTHER, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_OTHER, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT, BT_NMSTRT,
    BT_NMSTRT,
];
const UTF8_TAB: [u8; 128] = [
    BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL,
    BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL,
    BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL,
    BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL,
    BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL,
    BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL,
    BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL, BT_TRAIL,
    BT_TRAIL, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2,
    BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2,
    BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2,
    BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD2, BT_LEAD3, BT_LEAD3, BT_LEAD3,
    BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD3,
    BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD3, BT_LEAD4, BT_LEAD4, BT_LEAD4, BT_LEAD4, BT_LEAD4,
    BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML, BT_NONXML,
    BT_NONXML, BT_MALFORM, BT_MALFORM,
];
static NAMING_BITMAP: [u32; 320] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0x00000000, 0x04000000, 0x87FFFFFE, 0x07FFFFFE, 0x00000000, 0x00000000, 0xFF7FFFFF, 0xFF7FFFFF,
    0xFFFFFFFF, 0x7FF3FFFF, 0xFFFFFDFE, 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFE00F, 0xFC31FFFF,
    0x00FFFFFF, 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xF80001FF, 0x00000003, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFD740, 0xFFFFFFFB, 0x547F7FFF, 0x000FFFFD,
    0xFFFFDFFE, 0xFFFFFFFF, 0xDFFEFFFF, 0xFFFFFFFF, 0xFFFF0003, 0xFFFFFFFF, 0xFFFF199F, 0x033FCFFF,
    0x00000000, 0xFFFE0000, 0x027FFFFF, 0xFFFFFFFE, 0x0000007F, 0x00000000, 0xFFFF0000, 0x000707FF,
    0x00000000, 0x07FFFFFE, 0x000007FE, 0xFFFE0000, 0xFFFFFFFF, 0x7CFFFFFF, 0x002F7FFF, 0x00000060,
    0xFFFFFFE0, 0x23FFFFFF, 0xFF000000, 0x00000003, 0xFFF99FE0, 0x03C5FDFF, 0xB0000000, 0x00030003,
    0xFFF987E0, 0x036DFDFF, 0x5E000000, 0x001C0000, 0xFFFBAFE0, 0x23EDFDFF, 0x00000000, 0x00000001,
    0xFFF99FE0, 0x23CDFDFF, 0xB0000000, 0x00000003, 0xD63DC7E0, 0x03BFC718, 0x00000000, 0x00000000,
    0xFFFDDFE0, 0x03EFFDFF, 0x00000000, 0x00000003, 0xFFFDDFE0, 0x03EFFDFF, 0x40000000, 0x00000003,
    0xFFFDDFE0, 0x03FFFDFF, 0x00000000, 0x00000003, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFFFFFFFE, 0x000D7FFF, 0x0000003F, 0x00000000, 0xFEF02596, 0x200D6CAE, 0x0000001F, 0x00000000,
    0x00000000, 0x00000000, 0xFFFFFEFF, 0x000003FF, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFF003F, 0x007FFFFF,
    0x0007DAED, 0x50000000, 0x82315001, 0x002C62AB, 0x40000000, 0xF580C900, 0x00000007, 0x02010800,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x03FFFFFF,
    0x3F3FFFFF, 0xFFFFFFFF, 0xAAFF3F3F, 0x3FFFFFFF, 0xFFFFFFFF, 0x5FDFFFFF, 0x0FCF1FDC, 0x1FDC1FFF,
    0x00000000, 0x00004C40, 0x00000000, 0x00000000, 0x00000007, 0x00000000, 0x00000000, 0x00000000,
    0x00000080, 0x000003FE, 0xFFFFFFFE, 0xFFFFFFFF, 0x001FFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0x07FFFFFF,
    0xFFFFFFE0, 0x00001FFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000003F, 0x00000000, 0x00000000,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0000000F, 0x00000000, 0x00000000,
    0x00000000, 0x07FF6000, 0x87FFFFFE, 0x07FFFFFE, 0x00000000, 0x00800000, 0xFF7FFFFF, 0xFF7FFFFF,
    0x00FFFFFF, 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xF80001FF, 0x00030003, 0x00000000,
    0xFFFFFFFF, 0xFFFFFFFF, 0x0000003F, 0x00000003, 0xFFFFD7C0, 0xFFFFFFFB, 0x547F7FFF, 0x000FFFFD,
    0xFFFFDFFE, 0xFFFFFFFF, 0xDFFEFFFF, 0xFFFFFFFF, 0xFFFF007B, 0xFFFFFFFF, 0xFFFF199F, 0x033FCFFF,
    0x00000000, 0xFFFE0000, 0x027FFFFF, 0xFFFFFFFE, 0xFFFE007F, 0xBBFFFFFB, 0xFFFF0016, 0x000707FF,
    0x00000000, 0x07FFFFFE, 0x0007FFFF, 0xFFFF03FF, 0xFFFFFFFF, 0x7CFFFFFF, 0xFFEF7FFF, 0x03FF3DFF,
    0xFFFFFFEE, 0xF3FFFFFF, 0xFF1E3FFF, 0x0000FFCF, 0xFFF99FEE, 0xD3C5FDFF, 0xB080399F, 0x0003FFCF,
    0xFFF987E4, 0xD36DFDFF, 0x5E003987, 0x001FFFC0, 0xFFFBAFEE, 0xF3EDFDFF, 0x00003BBF, 0x0000FFC1,
    0xFFF99FEE, 0xF3CDFDFF, 0xB0C0398F, 0x0000FFC3, 0xD63DC7EC, 0xC3BFC718, 0x00803DC7, 0x0000FF80,
    0xFFFDDFEE, 0xC3EFFDFF, 0x00603DDF, 0x0000FFC3, 0xFFFDDFEC, 0xC3EFFDFF, 0x40603DDF, 0x0000FFC3,
    0xFFFDDFEC, 0xC3FFFDFF, 0x00803DCF, 0x0000FFC3, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0xFFFFFFFE, 0x07FF7FFF, 0x03FF7FFF, 0x00000000, 0xFEF02596, 0x3BFF6CAE, 0x03FF3F5F, 0x00000000,
    0x03000000, 0xC2A003FF, 0xFFFFFEFF, 0xFFFE03FF, 0xFEBF0FDF, 0x02FE3FFF, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x1FFF0000, 0x00000002,
    0x000000A0, 0x003EFFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0x661FFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0x77FFFFFF,
];
static NMSTRT_PAGES: [u8; 256] = [
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x13,
    0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x15, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x17,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
static NAME_PAGES: [u8; 256] = [
    0x19, 0x03, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x00, 0x00, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x10, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x13,
    0x26, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x27, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x17,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const fn table(low: &[u8; 128], high: &[u8; 128]) -> [u8; 256] {
    let mut out = [BT_NONXML; 256];
    let mut i = 0;
    while i < 128 {
        out[i] = low[i];
        out[i + 128] = high[i];
        i += 1;
    }
    out
}

static UTF8_TYPES: [u8; 256] = table(&ASCII_TAB, &UTF8_TAB);
static INTERNAL_UTF8_TYPES: [u8; 256] = table(&IASCII_TAB, &UTF8_TAB);
static LATIN1_TYPES: [u8; 256] = table(&ASCII_TAB, &LATIN1_TAB);
static ASCII_TYPES: [u8; 256] = table(&ASCII_TAB, &[BT_NONXML; 128]);

const TOK_TRAILING_RSQB: i32 = -5;
const TOK_NONE: i32 = -4;
const TOK_TRAILING_CR: i32 = -3;
const TOK_PARTIAL_CHAR: i32 = -2;
const TOK_PARTIAL: i32 = -1;
const TOK_INVALID: i32 = 0;
const TOK_START_TAG_WITH_ATTS: i32 = 1;
const TOK_START_TAG_NO_ATTS: i32 = 2;
const TOK_EMPTY_ELEMENT_WITH_ATTS: i32 = 3;
const TOK_EMPTY_ELEMENT_NO_ATTS: i32 = 4;
const TOK_END_TAG: i32 = 5;
const TOK_DATA_CHARS: i32 = 6;
const TOK_DATA_NEWLINE: i32 = 7;
const TOK_CDATA_SECT_OPEN: i32 = 8;
const TOK_ENTITY_REF: i32 = 9;
const TOK_CHAR_REF: i32 = 10;
const TOK_PI: i32 = 11;
const TOK_XML_DECL: i32 = 12;
const TOK_COMMENT: i32 = 13;
const TOK_BOM: i32 = 14;
const TOK_PROLOG_S: i32 = 15;
const TOK_DECL_OPEN: i32 = 16;
const TOK_DECL_CLOSE: i32 = 17;
const TOK_NAME: i32 = 18;
const TOK_NMTOKEN: i32 = 19;
const TOK_POUND_NAME: i32 = 20;
const TOK_OR: i32 = 21;
const TOK_PERCENT: i32 = 22;
const TOK_OPEN_PAREN: i32 = 23;
const TOK_CLOSE_PAREN: i32 = 24;
const TOK_OPEN_BRACKET: i32 = 25;
const TOK_CLOSE_BRACKET: i32 = 26;
const TOK_LITERAL: i32 = 27;
const TOK_PARAM_ENTITY_REF: i32 = 28;
const TOK_INSTANCE_START: i32 = 29;
const TOK_NAME_QUESTION: i32 = 30;
const TOK_NAME_ASTERISK: i32 = 31;
const TOK_NAME_PLUS: i32 = 32;
const TOK_COND_SECT_OPEN: i32 = 33;
const TOK_COND_SECT_CLOSE: i32 = 34;
const TOK_CLOSE_PAREN_QUESTION: i32 = 35;
const TOK_CLOSE_PAREN_ASTERISK: i32 = 36;
const TOK_CLOSE_PAREN_PLUS: i32 = 37;
const TOK_COMMA: i32 = 38;
const TOK_ATTRIBUTE_VALUE_S: i32 = 39;
const TOK_CDATA_SECT_CLOSE: i32 = 40;
const TOK_PREFIXED_NAME: i32 = 41;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Utf8,
    Ascii,
    Latin1,
    Little2,
    Big2,
    /// One byte a character, by a table, from the unknown-encoding handler.
    Table,
}

/// An `ENCODING`: byte types, and how its characters look.
struct Encoding {
    form: Form,
    /// `MINBPC`.
    m: usize,
    types: [u8; 256],
    /// For `Form::Table`: the code point of each byte, -1 when there isn't one.
    map: [i32; 256],
}

/// The result of one step of a scanner's switch on the byte type.
enum Step {
    Go,
    Stop(i32),
    Other,
}

macro_rules! req {
    ($self:ident, $ptr:expr, $end:expr, $count:expr) => {
        if !$self.has($ptr, $end, $count) {
            return TOK_PARTIAL;
        }
    };
}

/// CHECK_NAME_CASES in a loop.
macro_rules! name_step {
    ($self:ident, $t:expr, $d:expr, $ptr:ident, $end:expr, $next:ident) => {
        match $self.name_case($t, $d, &mut $ptr, $end, $next) {
            Step::Go => continue,
            Step::Stop(tok) => return tok,
            Step::Other => {}
        }
    };
}

/// CHECK_NMSTRT_CASES, with `default:` an invalid token.
macro_rules! nmstrt_or_invalid {
    ($self:ident, $t:expr, $d:expr, $ptr:ident, $end:expr, $next:ident) => {
        match $self.nmstrt_case($t, $d, &mut $ptr, $end, $next) {
            Step::Go => {}
            Step::Stop(tok) => return tok,
            Step::Other => {
                *$next = $ptr;
                return TOK_INVALID;
            }
        }
    };
}

fn byte(d: &[u8], at: usize) -> u8 {
    d.get(at).copied().unwrap_or(0)
}

fn slice(d: &[u8], from: usize, to: usize) -> &[u8] {
    d.get(from..to).unwrap_or(&[])
}

fn naming(pages: &[u8; 256], hi: u8, lo: u8) -> bool {
    let index = ((pages[hi as usize] as usize) << 3) + ((lo as usize) >> 5);
    NAMING_BITMAP.get(index).copied().unwrap_or(0) & (1u32 << (lo & 0x1F)) != 0
}

fn utf8_naming2(pages: &[u8; 256], p0: u8, p1: u8) -> bool {
    let index = ((pages[((p0 >> 2) & 7) as usize] as usize) << 3)
        + (((p0 & 3) as usize) << 1)
        + (((p1 >> 5) & 1) as usize);
    NAMING_BITMAP.get(index).copied().unwrap_or(0) & (1u32 << (p1 & 0x1F)) != 0
}

fn utf8_naming3(pages: &[u8; 256], p0: u8, p1: u8, p2: u8) -> bool {
    let page = (((p0 & 0xF) as usize) << 4) + (((p1 >> 2) & 0xF) as usize);
    let index =
        ((pages[page] as usize) << 3) + (((p1 & 3) as usize) << 1) + (((p2 >> 5) & 1) as usize);
    NAMING_BITMAP.get(index).copied().unwrap_or(0) & (1u32 << (p2 & 0x1F)) != 0
}

fn check_char_ref(result: i32) -> i32 {
    match result >> 8 {
        0xD8..=0xDF => -1,
        0 => {
            if LATIN1_TYPES[result as usize & 0xFF] == BT_NONXML {
                -1
            } else {
                result
            }
        }
        0xFF if result == 0xFFFE || result == 0xFFFF => -1,
        _ => result,
    }
}

fn encode_utf8(c: i32, out: &mut Vec<u8>) {
    let c = c as u32;
    if c < 0x80 {
        out.push(c as u8);
    } else if c < 0x800 {
        out.push(((c >> 6) | 0xC0) as u8);
        out.push(((c & 0x3F) | 0x80) as u8);
    } else if c < 0x10000 {
        out.push(((c >> 12) | 0xE0) as u8);
        out.push((((c >> 6) & 0x3F) | 0x80) as u8);
        out.push(((c & 0x3F) | 0x80) as u8);
    } else if c < 0x110000 {
        out.push(((c >> 18) | 0xF0) as u8);
        out.push((((c >> 12) & 0x3F) | 0x80) as u8);
        out.push((((c >> 6) & 0x3F) | 0x80) as u8);
        out.push(((c & 0x3F) | 0x80) as u8);
    }
}

impl Encoding {
    fn new(form: Form, types: &[u8; 256]) -> Encoding {
        let m = if matches!(form, Form::Little2 | Form::Big2) {
            2
        } else {
            1
        };
        Encoding {
            form,
            m,
            types: *types,
            map: [-1; 256],
        }
    }

    /// `XmlInitUnknownEncodingNS` for a table of one-byte characters.
    fn unknown(table: &[i32; 256]) -> Option<Encoding> {
        let latin1 = &LATIN1_TYPES;
        for i in 0..128 {
            if latin1[i] != BT_OTHER && latin1[i] != BT_NONXML && table[i] != i as i32 {
                return None;
            }
        }
        let mut encoding = Encoding::new(Form::Table, latin1);
        for (i, &c) in table.iter().enumerate() {
            encoding.map[i] = c;
            if c == -1 {
                encoding.types[i] = BT_MALFORM;
            } else if c < 0x80 {
                let t = latin1[c as usize];
                if t != BT_OTHER && t != BT_NONXML && c != i as i32 {
                    return None;
                }
                encoding.types[i] = t;
            } else if check_char_ref(c) < 0 {
                encoding.types[i] = BT_NONXML;
            } else {
                if c > 0xFFFF {
                    return None;
                }
                let (hi, lo) = ((c >> 8) as u8, c as u8);
                encoding.types[i] = if naming(&NMSTRT_PAGES, hi, lo) {
                    BT_NMSTRT
                } else if naming(&NAME_PAGES, hi, lo) {
                    BT_NAME
                } else {
                    BT_OTHER
                };
            }
        }
        encoding.types[b':' as usize] = BT_COLON;
        Some(encoding)
    }

    fn has(&self, ptr: usize, end: usize, count: usize) -> bool {
        ptr.saturating_add(count * self.m) <= end
    }

    /// `BYTE_TYPE`.
    fn bt(&self, d: &[u8], p: usize) -> u8 {
        match self.form {
            Form::Little2 => self.two_type(byte(d, p + 1), byte(d, p)),
            Form::Big2 => self.two_type(byte(d, p), byte(d, p + 1)),
            _ => self.types[byte(d, p) as usize],
        }
    }

    fn two_type(&self, hi: u8, lo: u8) -> u8 {
        match hi {
            0 => self.types[lo as usize],
            0xD8..=0xDB => BT_LEAD4,
            0xDC..=0xDF => BT_TRAIL,
            0xFF if lo == 0xFF || lo == 0xFE => BT_NONXML,
            _ => BT_NONASCII,
        }
    }

    /// `(hi, lo)` of a two-byte character.
    fn two(&self, d: &[u8], p: usize) -> (u8, u8) {
        if self.form == Form::Little2 {
            (byte(d, p + 1), byte(d, p))
        } else {
            (byte(d, p), byte(d, p + 1))
        }
    }

    /// `CHAR_MATCHES`.
    fn matches(&self, d: &[u8], p: usize, c: u8) -> bool {
        match self.form {
            Form::Little2 => byte(d, p + 1) == 0 && byte(d, p) == c,
            Form::Big2 => byte(d, p) == 0 && byte(d, p + 1) == c,
            _ => byte(d, p) == c,
        }
    }

    /// `BYTE_TO_ASCII`.
    fn ascii(&self, d: &[u8], p: usize) -> i32 {
        match self.form {
            Form::Little2 | Form::Big2 => {
                let (hi, lo) = self.two(d, p);
                if hi == 0 { i32::from(lo as i8) } else { -1 }
            }
            _ => i32::from(byte(d, p) as i8),
        }
    }

    fn is_invalid(&self, d: &[u8], p: usize, n: usize) -> bool {
        match self.form {
            Form::Utf8 => {
                let (p0, p1, p2, p3) = (byte(d, p), byte(d, p + 1), byte(d, p + 2), byte(d, p + 3));
                match n {
                    2 => p0 < 0xC2 || p1 & 0x80 == 0 || p1 & 0xC0 == 0xC0,
                    3 => {
                        p2 & 0x80 == 0
                            || if p0 == 0xEF && p1 == 0xBF {
                                p2 > 0xBD
                            } else {
                                p2 & 0xC0 == 0xC0
                            }
                            || if p0 == 0xE0 {
                                p1 < 0xA0 || p1 & 0xC0 == 0xC0
                            } else {
                                p1 & 0x80 == 0
                                    || if p0 == 0xED {
                                        p1 > 0x9F
                                    } else {
                                        p1 & 0xC0 == 0xC0
                                    }
                            }
                    }
                    _ => {
                        p3 & 0x80 == 0
                            || p3 & 0xC0 == 0xC0
                            || p2 & 0x80 == 0
                            || p2 & 0xC0 == 0xC0
                            || if p0 == 0xF0 {
                                p1 < 0x90 || p1 & 0xC0 == 0xC0
                            } else {
                                p1 & 0x80 == 0
                                    || if p0 == 0xF4 {
                                        p1 > 0x8F
                                    } else {
                                        p1 & 0xC0 == 0xC0
                                    }
                            }
                    }
                }
            }
            Form::Little2 => n == 4 && byte(d, p + 3) & 0xFC != 0xDC,
            Form::Big2 => n == 4 && byte(d, p + 2) & 0xFC != 0xDC,
            _ => false,
        }
    }

    fn is_name(&self, d: &[u8], p: usize, n: usize) -> bool {
        if self.form != Form::Utf8 {
            return false;
        }
        match n {
            2 => utf8_naming2(&NAME_PAGES, byte(d, p), byte(d, p + 1)),
            3 => utf8_naming3(&NAME_PAGES, byte(d, p), byte(d, p + 1), byte(d, p + 2)),
            _ => false,
        }
    }

    fn is_nmstrt(&self, d: &[u8], p: usize, n: usize) -> bool {
        if self.form != Form::Utf8 {
            return false;
        }
        match n {
            2 => utf8_naming2(&NMSTRT_PAGES, byte(d, p), byte(d, p + 1)),
            3 => utf8_naming3(&NMSTRT_PAGES, byte(d, p), byte(d, p + 1), byte(d, p + 2)),
            _ => false,
        }
    }

    fn is_name_m(&self, d: &[u8], p: usize) -> bool {
        match self.form {
            Form::Little2 | Form::Big2 => {
                let (hi, lo) = self.two(d, p);
                naming(&NAME_PAGES, hi, lo)
            }
            _ => false,
        }
    }

    fn is_nmstrt_m(&self, d: &[u8], p: usize) -> bool {
        match self.form {
            Form::Little2 | Form::Big2 => {
                let (hi, lo) = self.two(d, p);
                naming(&NMSTRT_PAGES, hi, lo)
            }
            _ => false,
        }
    }

    /// CHECK_NAME_CASES.
    fn name_case(&self, t: u8, d: &[u8], ptr: &mut usize, end: usize, next: &mut usize) -> Step {
        match t {
            BT_NONASCII => {
                if !self.is_name_m(d, *ptr) {
                    *next = *ptr;
                    return Step::Stop(TOK_INVALID);
                }
                *ptr += self.m;
                Step::Go
            }
            BT_NMSTRT | BT_HEX | BT_DIGIT | BT_NAME | BT_MINUS => {
                *ptr += self.m;
                Step::Go
            }
            BT_LEAD2 | BT_LEAD3 | BT_LEAD4 => {
                let n = (t - BT_LEAD2 + 2) as usize;
                if end - *ptr < n {
                    return Step::Stop(TOK_PARTIAL_CHAR);
                }
                if self.is_invalid(d, *ptr, n) || !self.is_name(d, *ptr, n) {
                    *next = *ptr;
                    return Step::Stop(TOK_INVALID);
                }
                *ptr += n;
                Step::Go
            }
            _ => Step::Other,
        }
    }

    /// CHECK_NMSTRT_CASES.
    fn nmstrt_case(&self, t: u8, d: &[u8], ptr: &mut usize, end: usize, next: &mut usize) -> Step {
        match t {
            BT_NONASCII => {
                if !self.is_nmstrt_m(d, *ptr) {
                    *next = *ptr;
                    return Step::Stop(TOK_INVALID);
                }
                *ptr += self.m;
                Step::Go
            }
            BT_NMSTRT | BT_HEX => {
                *ptr += self.m;
                Step::Go
            }
            BT_LEAD2 | BT_LEAD3 | BT_LEAD4 => {
                let n = (t - BT_LEAD2 + 2) as usize;
                if end - *ptr < n {
                    return Step::Stop(TOK_PARTIAL_CHAR);
                }
                if self.is_invalid(d, *ptr, n) || !self.is_nmstrt(d, *ptr, n) {
                    *next = *ptr;
                    return Step::Stop(TOK_INVALID);
                }
                *ptr += n;
                Step::Go
            }
            _ => Step::Other,
        }
    }

    /// INVALID_CASES.
    fn invalid_case(&self, t: u8, d: &[u8], ptr: &mut usize, end: usize, next: &mut usize) -> Step {
        match t {
            BT_LEAD2 | BT_LEAD3 | BT_LEAD4 => {
                let n = (t - BT_LEAD2 + 2) as usize;
                if end - *ptr < n {
                    return Step::Stop(TOK_PARTIAL_CHAR);
                }
                if self.is_invalid(d, *ptr, n) {
                    *next = *ptr;
                    return Step::Stop(TOK_INVALID);
                }
                *ptr += n;
                Step::Go
            }
            BT_NONXML | BT_MALFORM | BT_TRAIL => {
                *next = *ptr;
                Step::Stop(TOK_INVALID)
            }
            _ => Step::Other,
        }
    }

    fn scan_comment(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if self.has(ptr, end, 1) {
            if !self.matches(d, ptr, b'-') {
                *next = ptr;
                return TOK_INVALID;
            }
            ptr += m;
            while self.has(ptr, end, 1) {
                let t = self.bt(d, ptr);
                match self.invalid_case(t, d, &mut ptr, end, next) {
                    Step::Go => continue,
                    Step::Stop(tok) => return tok,
                    Step::Other => {}
                }
                if t == BT_MINUS {
                    ptr += m;
                    req!(self, ptr, end, 1);
                    if self.matches(d, ptr, b'-') {
                        ptr += m;
                        req!(self, ptr, end, 1);
                        if !self.matches(d, ptr, b'>') {
                            *next = ptr;
                            return TOK_INVALID;
                        }
                        *next = ptr + m;
                        return TOK_COMMENT;
                    }
                } else {
                    ptr += m;
                }
            }
        }
        TOK_PARTIAL
    }

    fn scan_decl(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        req!(self, ptr, end, 1);
        match self.bt(d, ptr) {
            BT_MINUS => return self.scan_comment(d, ptr + m, end, next),
            BT_LSQB => {
                *next = ptr + m;
                return TOK_COND_SECT_OPEN;
            }
            BT_NMSTRT | BT_HEX => ptr += m,
            _ => {
                *next = ptr;
                return TOK_INVALID;
            }
        }
        while self.has(ptr, end, 1) {
            match self.bt(d, ptr) {
                BT_PERCNT => {
                    req!(self, ptr, end, 2);
                    // don't allow <!ENTITY% foo "whatever">
                    if matches!(self.bt(d, ptr + m), BT_S | BT_CR | BT_LF | BT_PERCNT) {
                        *next = ptr;
                        return TOK_INVALID;
                    }
                    *next = ptr;
                    return TOK_DECL_OPEN;
                }
                BT_S | BT_CR | BT_LF => {
                    *next = ptr;
                    return TOK_DECL_OPEN;
                }
                BT_NMSTRT | BT_HEX => ptr += m,
                _ => {
                    *next = ptr;
                    return TOK_INVALID;
                }
            }
        }
        TOK_PARTIAL
    }

    /// `checkPiTarget`: `Err(())` for a target that is a case variant of `xml`.
    fn check_pi_target(&self, d: &[u8], ptr: usize, end: usize) -> Result<i32, ()> {
        let m = self.m;
        if end - ptr != m * 3 {
            return Ok(TOK_PI);
        }
        let mut upper = false;
        for (at, lower, capital) in [
            (ptr, b'x', b'X'),
            (ptr + m, b'm', b'M'),
            (ptr + 2 * m, b'l', b'L'),
        ] {
            let c = self.ascii(d, at);
            if c == i32::from(capital) {
                upper = true;
            } else if c != i32::from(lower) {
                return Ok(TOK_PI);
            }
        }
        if upper { Err(()) } else { Ok(TOK_XML_DECL) }
    }

    fn scan_pi(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        let target = ptr;
        req!(self, ptr, end, 1);
        let t = self.bt(d, ptr);
        nmstrt_or_invalid!(self, t, d, ptr, end, next);
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            match t {
                BT_S | BT_CR | BT_LF => {
                    let Ok(tok) = self.check_pi_target(d, target, ptr) else {
                        *next = ptr;
                        return TOK_INVALID;
                    };
                    ptr += m;
                    while self.has(ptr, end, 1) {
                        let t = self.bt(d, ptr);
                        match self.invalid_case(t, d, &mut ptr, end, next) {
                            Step::Go => continue,
                            Step::Stop(tok) => return tok,
                            Step::Other => {}
                        }
                        if t == BT_QUEST {
                            ptr += m;
                            req!(self, ptr, end, 1);
                            if self.matches(d, ptr, b'>') {
                                *next = ptr + m;
                                return tok;
                            }
                        } else {
                            ptr += m;
                        }
                    }
                    return TOK_PARTIAL;
                }
                BT_QUEST => {
                    let Ok(tok) = self.check_pi_target(d, target, ptr) else {
                        *next = ptr;
                        return TOK_INVALID;
                    };
                    ptr += m;
                    req!(self, ptr, end, 1);
                    if self.matches(d, ptr, b'>') {
                        *next = ptr + m;
                        return tok;
                    }
                    *next = ptr;
                    return TOK_INVALID;
                }
                _ => {
                    *next = ptr;
                    return TOK_INVALID;
                }
            }
        }
        TOK_PARTIAL
    }

    fn scan_cdata_section(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        req!(self, ptr, end, 6);
        for c in b"CDATA[" {
            if !self.matches(d, ptr, *c) {
                *next = ptr;
                return TOK_INVALID;
            }
            ptr += self.m;
        }
        *next = ptr;
        TOK_CDATA_SECT_OPEN
    }

    /// The end of the data rounded down to whole characters, or `None` when none is left.
    fn aligned_end(&self, ptr: usize, end: usize) -> Option<usize> {
        if self.m > 1 {
            let n = end - ptr;
            if n & (self.m - 1) != 0 {
                let n = n & !(self.m - 1);
                if n == 0 {
                    return None;
                }
                return Some(ptr + n);
            }
        }
        Some(end)
    }

    fn cdata_section_tok(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if ptr >= end {
            return TOK_NONE;
        }
        let Some(end) = self.aligned_end(ptr, end) else {
            return TOK_PARTIAL;
        };
        let t = self.bt(d, ptr);
        match self.invalid_case(t, d, &mut ptr, end, next) {
            Step::Go => {}
            Step::Stop(tok) => return tok,
            Step::Other => match t {
                BT_RSQB => {
                    ptr += m;
                    req!(self, ptr, end, 1);
                    if self.matches(d, ptr, b']') {
                        ptr += m;
                        req!(self, ptr, end, 1);
                        if self.matches(d, ptr, b'>') {
                            *next = ptr + m;
                            return TOK_CDATA_SECT_CLOSE;
                        }
                        ptr -= m;
                    }
                }
                BT_CR => {
                    ptr += m;
                    req!(self, ptr, end, 1);
                    if self.bt(d, ptr) == BT_LF {
                        ptr += m;
                    }
                    *next = ptr;
                    return TOK_DATA_NEWLINE;
                }
                BT_LF => {
                    *next = ptr + m;
                    return TOK_DATA_NEWLINE;
                }
                _ => ptr += m,
            },
        }
        while self.has(ptr, end, 1) {
            match self.bt(d, ptr) {
                t @ (BT_LEAD2 | BT_LEAD3 | BT_LEAD4) => {
                    let n = (t - BT_LEAD2 + 2) as usize;
                    if end - ptr < n || self.is_invalid(d, ptr, n) {
                        *next = ptr;
                        return TOK_DATA_CHARS;
                    }
                    ptr += n;
                }
                BT_NONXML | BT_MALFORM | BT_TRAIL | BT_CR | BT_LF | BT_RSQB => {
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                _ => ptr += m,
            }
        }
        *next = ptr;
        TOK_DATA_CHARS
    }

    fn scan_end_tag(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        req!(self, ptr, end, 1);
        let t = self.bt(d, ptr);
        nmstrt_or_invalid!(self, t, d, ptr, end, next);
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            match t {
                BT_S | BT_CR | BT_LF => {
                    ptr += m;
                    while self.has(ptr, end, 1) {
                        match self.bt(d, ptr) {
                            BT_S | BT_CR | BT_LF => {}
                            BT_GT => {
                                *next = ptr + m;
                                return TOK_END_TAG;
                            }
                            _ => {
                                *next = ptr;
                                return TOK_INVALID;
                            }
                        }
                        ptr += m;
                    }
                    return TOK_PARTIAL;
                }
                // no need to check qname syntax here, since the end tag must match exactly
                BT_COLON => ptr += m,
                BT_GT => {
                    *next = ptr + m;
                    return TOK_END_TAG;
                }
                _ => {
                    *next = ptr;
                    return TOK_INVALID;
                }
            }
        }
        TOK_PARTIAL
    }

    fn scan_hex_char_ref(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if self.has(ptr, end, 1) {
            if !matches!(self.bt(d, ptr), BT_DIGIT | BT_HEX) {
                *next = ptr;
                return TOK_INVALID;
            }
            ptr += m;
            while self.has(ptr, end, 1) {
                match self.bt(d, ptr) {
                    BT_DIGIT | BT_HEX => {}
                    BT_SEMI => {
                        *next = ptr + m;
                        return TOK_CHAR_REF;
                    }
                    _ => {
                        *next = ptr;
                        return TOK_INVALID;
                    }
                }
                ptr += m;
            }
        }
        TOK_PARTIAL
    }

    fn scan_char_ref(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if self.has(ptr, end, 1) {
            if self.matches(d, ptr, b'x') {
                return self.scan_hex_char_ref(d, ptr + m, end, next);
            }
            if self.bt(d, ptr) != BT_DIGIT {
                *next = ptr;
                return TOK_INVALID;
            }
            ptr += m;
            while self.has(ptr, end, 1) {
                match self.bt(d, ptr) {
                    BT_DIGIT => {}
                    BT_SEMI => {
                        *next = ptr + m;
                        return TOK_CHAR_REF;
                    }
                    _ => {
                        *next = ptr;
                        return TOK_INVALID;
                    }
                }
                ptr += m;
            }
        }
        TOK_PARTIAL
    }

    fn scan_ref(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        req!(self, ptr, end, 1);
        let t = self.bt(d, ptr);
        if t == BT_NUM {
            return self.scan_char_ref(d, ptr + m, end, next);
        }
        nmstrt_or_invalid!(self, t, d, ptr, end, next);
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            if t == BT_SEMI {
                *next = ptr + m;
                return TOK_ENTITY_REF;
            }
            *next = ptr;
            return TOK_INVALID;
        }
        TOK_PARTIAL
    }

    /// The `sol:` label: `ptr` is at the `/` of a tag.
    fn scan_sol(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize, tok: i32) -> i32 {
        ptr += self.m;
        req!(self, ptr, end, 1);
        if !self.matches(d, ptr, b'>') {
            *next = ptr;
            return TOK_INVALID;
        }
        *next = ptr + self.m;
        tok
    }

    fn scan_atts(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        let mut had_colon = false;
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            match t {
                BT_COLON => {
                    if had_colon {
                        *next = ptr;
                        return TOK_INVALID;
                    }
                    had_colon = true;
                    ptr += m;
                    req!(self, ptr, end, 1);
                    let t = self.bt(d, ptr);
                    nmstrt_or_invalid!(self, t, d, ptr, end, next);
                }
                BT_S | BT_CR | BT_LF | BT_EQUALS => {
                    if t != BT_EQUALS {
                        loop {
                            ptr += m;
                            req!(self, ptr, end, 1);
                            let t = self.bt(d, ptr);
                            if t == BT_EQUALS {
                                break;
                            }
                            if !matches!(t, BT_S | BT_LF | BT_CR) {
                                *next = ptr;
                                return TOK_INVALID;
                            }
                        }
                    }
                    had_colon = false;
                    let open = loop {
                        ptr += m;
                        req!(self, ptr, end, 1);
                        let open = self.bt(d, ptr);
                        if open == BT_QUOT || open == BT_APOS {
                            break open;
                        }
                        if !matches!(open, BT_S | BT_LF | BT_CR) {
                            *next = ptr;
                            return TOK_INVALID;
                        }
                    };
                    ptr += m;
                    // in attribute value
                    loop {
                        req!(self, ptr, end, 1);
                        let t = self.bt(d, ptr);
                        if t == open {
                            break;
                        }
                        match self.invalid_case(t, d, &mut ptr, end, next) {
                            Step::Go => continue,
                            Step::Stop(tok) => return tok,
                            Step::Other => {}
                        }
                        match t {
                            BT_AMP => {
                                let mut after = ptr;
                                let tok = self.scan_ref(d, ptr + m, end, &mut after);
                                ptr = after;
                                if tok <= 0 {
                                    if tok == TOK_INVALID {
                                        *next = ptr;
                                    }
                                    return tok;
                                }
                            }
                            BT_LT => {
                                *next = ptr;
                                return TOK_INVALID;
                            }
                            _ => ptr += m,
                        }
                    }
                    ptr += m;
                    req!(self, ptr, end, 1);
                    match self.bt(d, ptr) {
                        BT_S | BT_CR | BT_LF => {}
                        BT_SOL => {
                            return self.scan_sol(d, ptr, end, next, TOK_EMPTY_ELEMENT_WITH_ATTS);
                        }
                        BT_GT => {
                            *next = ptr + m;
                            return TOK_START_TAG_WITH_ATTS;
                        }
                        _ => {
                            *next = ptr;
                            return TOK_INVALID;
                        }
                    }
                    // ptr points to the white space after the closing quote
                    loop {
                        ptr += m;
                        req!(self, ptr, end, 1);
                        let t = self.bt(d, ptr);
                        match self.nmstrt_case(t, d, &mut ptr, end, next) {
                            Step::Go => break,
                            Step::Stop(tok) => return tok,
                            Step::Other => {}
                        }
                        match t {
                            BT_S | BT_CR | BT_LF => {}
                            BT_GT => {
                                *next = ptr + m;
                                return TOK_START_TAG_WITH_ATTS;
                            }
                            BT_SOL => {
                                return self.scan_sol(
                                    d,
                                    ptr,
                                    end,
                                    next,
                                    TOK_EMPTY_ELEMENT_WITH_ATTS,
                                );
                            }
                            _ => {
                                *next = ptr;
                                return TOK_INVALID;
                            }
                        }
                    }
                }
                _ => {
                    *next = ptr;
                    return TOK_INVALID;
                }
            }
        }
        TOK_PARTIAL
    }

    fn scan_lt(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        req!(self, ptr, end, 1);
        let t = self.bt(d, ptr);
        match self.nmstrt_case(t, d, &mut ptr, end, next) {
            Step::Go => {}
            Step::Stop(tok) => return tok,
            Step::Other => match t {
                BT_EXCL => {
                    ptr += m;
                    req!(self, ptr, end, 1);
                    match self.bt(d, ptr) {
                        BT_MINUS => return self.scan_comment(d, ptr + m, end, next),
                        BT_LSQB => return self.scan_cdata_section(d, ptr + m, end, next),
                        _ => {}
                    }
                    *next = ptr;
                    return TOK_INVALID;
                }
                BT_QUEST => return self.scan_pi(d, ptr + m, end, next),
                BT_SOL => return self.scan_end_tag(d, ptr + m, end, next),
                _ => {
                    *next = ptr;
                    return TOK_INVALID;
                }
            },
        }
        let mut had_colon = false;
        // we have a start tag
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            match t {
                BT_COLON => {
                    if had_colon {
                        *next = ptr;
                        return TOK_INVALID;
                    }
                    had_colon = true;
                    ptr += m;
                    req!(self, ptr, end, 1);
                    let t = self.bt(d, ptr);
                    nmstrt_or_invalid!(self, t, d, ptr, end, next);
                }
                BT_S | BT_CR | BT_LF => {
                    ptr += m;
                    while self.has(ptr, end, 1) {
                        let t = self.bt(d, ptr);
                        match self.nmstrt_case(t, d, &mut ptr, end, next) {
                            Step::Go => return self.scan_atts(d, ptr, end, next),
                            Step::Stop(tok) => return tok,
                            Step::Other => {}
                        }
                        match t {
                            BT_GT => {
                                *next = ptr + m;
                                return TOK_START_TAG_NO_ATTS;
                            }
                            BT_SOL => {
                                return self.scan_sol(d, ptr, end, next, TOK_EMPTY_ELEMENT_NO_ATTS);
                            }
                            BT_S | BT_CR | BT_LF => ptr += m,
                            _ => {
                                *next = ptr;
                                return TOK_INVALID;
                            }
                        }
                    }
                    return TOK_PARTIAL;
                }
                BT_GT => {
                    *next = ptr + m;
                    return TOK_START_TAG_NO_ATTS;
                }
                BT_SOL => return self.scan_sol(d, ptr, end, next, TOK_EMPTY_ELEMENT_NO_ATTS),
                _ => {
                    *next = ptr;
                    return TOK_INVALID;
                }
            }
        }
        TOK_PARTIAL
    }

    fn content_tok(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if ptr >= end {
            return TOK_NONE;
        }
        let Some(end) = self.aligned_end(ptr, end) else {
            return TOK_PARTIAL;
        };
        let t = self.bt(d, ptr);
        match self.invalid_case(t, d, &mut ptr, end, next) {
            Step::Go => {}
            Step::Stop(tok) => return tok,
            Step::Other => match t {
                BT_LT => return self.scan_lt(d, ptr + m, end, next),
                BT_AMP => return self.scan_ref(d, ptr + m, end, next),
                BT_CR => {
                    ptr += m;
                    if !self.has(ptr, end, 1) {
                        return TOK_TRAILING_CR;
                    }
                    if self.bt(d, ptr) == BT_LF {
                        ptr += m;
                    }
                    *next = ptr;
                    return TOK_DATA_NEWLINE;
                }
                BT_LF => {
                    *next = ptr + m;
                    return TOK_DATA_NEWLINE;
                }
                BT_RSQB => {
                    ptr += m;
                    if !self.has(ptr, end, 1) {
                        return TOK_TRAILING_RSQB;
                    }
                    if self.matches(d, ptr, b']') {
                        ptr += m;
                        if !self.has(ptr, end, 1) {
                            return TOK_TRAILING_RSQB;
                        }
                        if self.matches(d, ptr, b'>') {
                            *next = ptr;
                            return TOK_INVALID;
                        }
                        ptr -= m;
                    }
                }
                _ => ptr += m,
            },
        }
        while self.has(ptr, end, 1) {
            match self.bt(d, ptr) {
                t @ (BT_LEAD2 | BT_LEAD3 | BT_LEAD4) => {
                    let n = (t - BT_LEAD2 + 2) as usize;
                    if end - ptr < n || self.is_invalid(d, ptr, n) {
                        *next = ptr;
                        return TOK_DATA_CHARS;
                    }
                    ptr += n;
                }
                BT_RSQB => {
                    if self.has(ptr, end, 2) {
                        if !self.matches(d, ptr + m, b']') {
                            ptr += m;
                            continue;
                        }
                        if self.has(ptr, end, 3) {
                            if !self.matches(d, ptr + 2 * m, b'>') {
                                ptr += m;
                                continue;
                            }
                            *next = ptr + 2 * m;
                            return TOK_INVALID;
                        }
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                BT_AMP | BT_LT | BT_NONXML | BT_MALFORM | BT_TRAIL | BT_CR | BT_LF => {
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                _ => ptr += m,
            }
        }
        *next = ptr;
        TOK_DATA_CHARS
    }

    fn scan_percent(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        req!(self, ptr, end, 1);
        let t = self.bt(d, ptr);
        match self.nmstrt_case(t, d, &mut ptr, end, next) {
            Step::Go => {}
            Step::Stop(tok) => return tok,
            Step::Other => {
                *next = ptr;
                return if matches!(t, BT_S | BT_LF | BT_CR | BT_PERCNT) {
                    TOK_PERCENT
                } else {
                    TOK_INVALID
                };
            }
        }
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            if t == BT_SEMI {
                *next = ptr + m;
                return TOK_PARAM_ENTITY_REF;
            }
            *next = ptr;
            return TOK_INVALID;
        }
        TOK_PARTIAL
    }

    fn scan_pound_name(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        req!(self, ptr, end, 1);
        let t = self.bt(d, ptr);
        nmstrt_or_invalid!(self, t, d, ptr, end, next);
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            *next = ptr;
            return if matches!(
                t,
                BT_CR | BT_LF | BT_S | BT_RPAR | BT_GT | BT_PERCNT | BT_VERBAR
            ) {
                TOK_POUND_NAME
            } else {
                TOK_INVALID
            };
        }
        -TOK_POUND_NAME
    }

    fn scan_lit(&self, open: u8, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            match self.invalid_case(t, d, &mut ptr, end, next) {
                Step::Go => continue,
                Step::Stop(tok) => return tok,
                Step::Other => {}
            }
            ptr += self.m;
            if t == BT_QUOT || t == BT_APOS {
                if t != open {
                    continue;
                }
                if !self.has(ptr, end, 1) {
                    return -TOK_LITERAL;
                }
                *next = ptr;
                return match self.bt(d, ptr) {
                    BT_S | BT_CR | BT_LF | BT_GT | BT_PERCNT | BT_LSQB => TOK_LITERAL,
                    _ => TOK_INVALID,
                };
            }
        }
        TOK_PARTIAL
    }

    fn prolog_tok(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if ptr >= end {
            return TOK_NONE;
        }
        let Some(end) = self.aligned_end(ptr, end) else {
            return TOK_PARTIAL;
        };
        let mut tok;
        let t = self.bt(d, ptr);
        match t {
            BT_QUOT => return self.scan_lit(BT_QUOT, d, ptr + m, end, next),
            BT_APOS => return self.scan_lit(BT_APOS, d, ptr + m, end, next),
            BT_LT => {
                ptr += m;
                req!(self, ptr, end, 1);
                match self.bt(d, ptr) {
                    BT_EXCL => return self.scan_decl(d, ptr + m, end, next),
                    BT_QUEST => return self.scan_pi(d, ptr + m, end, next),
                    BT_NMSTRT | BT_HEX | BT_NONASCII | BT_LEAD2 | BT_LEAD3 | BT_LEAD4 => {
                        *next = ptr - m;
                        return TOK_INSTANCE_START;
                    }
                    _ => {}
                }
                *next = ptr;
                return TOK_INVALID;
            }
            BT_CR | BT_S | BT_LF => {
                if t == BT_CR && ptr + m == end {
                    *next = end;
                    // indicate that this might be part of a CR/LF pair
                    return -TOK_PROLOG_S;
                }
                loop {
                    ptr += m;
                    if !self.has(ptr, end, 1) {
                        break;
                    }
                    match self.bt(d, ptr) {
                        BT_S | BT_LF => {}
                        // don't split CR/LF pair
                        BT_CR if ptr + m != end => {}
                        _ => {
                            *next = ptr;
                            return TOK_PROLOG_S;
                        }
                    }
                }
                *next = ptr;
                return TOK_PROLOG_S;
            }
            BT_PERCNT => return self.scan_percent(d, ptr + m, end, next),
            BT_COMMA => {
                *next = ptr + m;
                return TOK_COMMA;
            }
            BT_LSQB => {
                *next = ptr + m;
                return TOK_OPEN_BRACKET;
            }
            BT_RSQB => {
                ptr += m;
                if !self.has(ptr, end, 1) {
                    return -TOK_CLOSE_BRACKET;
                }
                if self.matches(d, ptr, b']') {
                    req!(self, ptr, end, 2);
                    if self.matches(d, ptr + m, b'>') {
                        *next = ptr + 2 * m;
                        return TOK_COND_SECT_CLOSE;
                    }
                }
                *next = ptr;
                return TOK_CLOSE_BRACKET;
            }
            BT_LPAR => {
                *next = ptr + m;
                return TOK_OPEN_PAREN;
            }
            BT_RPAR => {
                ptr += m;
                if !self.has(ptr, end, 1) {
                    return -TOK_CLOSE_PAREN;
                }
                match self.bt(d, ptr) {
                    BT_AST => {
                        *next = ptr + m;
                        return TOK_CLOSE_PAREN_ASTERISK;
                    }
                    BT_QUEST => {
                        *next = ptr + m;
                        return TOK_CLOSE_PAREN_QUESTION;
                    }
                    BT_PLUS => {
                        *next = ptr + m;
                        return TOK_CLOSE_PAREN_PLUS;
                    }
                    BT_CR | BT_LF | BT_S | BT_GT | BT_COMMA | BT_VERBAR | BT_RPAR => {
                        *next = ptr;
                        return TOK_CLOSE_PAREN;
                    }
                    _ => {}
                }
                *next = ptr;
                return TOK_INVALID;
            }
            BT_VERBAR => {
                *next = ptr + m;
                return TOK_OR;
            }
            BT_GT => {
                *next = ptr + m;
                return TOK_DECL_CLOSE;
            }
            BT_NUM => return self.scan_pound_name(d, ptr + m, end, next),
            BT_LEAD2 | BT_LEAD3 | BT_LEAD4 => {
                let n = (t - BT_LEAD2 + 2) as usize;
                if end - ptr < n {
                    return TOK_PARTIAL_CHAR;
                }
                if self.is_invalid(d, ptr, n) {
                    *next = ptr;
                    return TOK_INVALID;
                }
                if self.is_nmstrt(d, ptr, n) {
                    ptr += n;
                    tok = TOK_NAME;
                } else if self.is_name(d, ptr, n) {
                    ptr += n;
                    tok = TOK_NMTOKEN;
                } else {
                    *next = ptr;
                    return TOK_INVALID;
                }
            }
            BT_NMSTRT | BT_HEX => {
                tok = TOK_NAME;
                ptr += m;
            }
            BT_DIGIT | BT_NAME | BT_MINUS | BT_COLON => {
                tok = TOK_NMTOKEN;
                ptr += m;
            }
            BT_NONASCII if self.is_nmstrt_m(d, ptr) => {
                ptr += m;
                tok = TOK_NAME;
            }
            BT_NONASCII if self.is_name_m(d, ptr) => {
                ptr += m;
                tok = TOK_NMTOKEN;
            }
            _ => {
                *next = ptr;
                return TOK_INVALID;
            }
        }
        while self.has(ptr, end, 1) {
            let t = self.bt(d, ptr);
            name_step!(self, t, d, ptr, end, next);
            match t {
                BT_GT | BT_RPAR | BT_COMMA | BT_VERBAR | BT_LSQB | BT_PERCNT | BT_S | BT_CR
                | BT_LF => {
                    *next = ptr;
                    return tok;
                }
                BT_COLON => {
                    ptr += m;
                    if tok == TOK_NAME {
                        req!(self, ptr, end, 1);
                        tok = TOK_PREFIXED_NAME;
                        let t = self.bt(d, ptr);
                        match self.name_case(t, d, &mut ptr, end, next) {
                            Step::Go => {}
                            Step::Stop(stop) => return stop,
                            Step::Other => tok = TOK_NMTOKEN,
                        }
                    } else if tok == TOK_PREFIXED_NAME {
                        tok = TOK_NMTOKEN;
                    }
                }
                BT_PLUS | BT_AST | BT_QUEST => {
                    if tok == TOK_NMTOKEN {
                        *next = ptr;
                        return TOK_INVALID;
                    }
                    *next = ptr + m;
                    return match t {
                        BT_PLUS => TOK_NAME_PLUS,
                        BT_AST => TOK_NAME_ASTERISK,
                        _ => TOK_NAME_QUESTION,
                    };
                }
                _ => {
                    *next = ptr;
                    return TOK_INVALID;
                }
            }
        }
        -tok
    }

    fn attribute_value_tok(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if ptr >= end {
            return TOK_NONE;
        }
        if !self.has(ptr, end, 1) {
            return TOK_PARTIAL;
        }
        let start = ptr;
        while self.has(ptr, end, 1) {
            match self.bt(d, ptr) {
                t @ (BT_LEAD2 | BT_LEAD3 | BT_LEAD4) => ptr += (t - BT_LEAD2 + 2) as usize,
                BT_AMP => {
                    if ptr == start {
                        return self.scan_ref(d, ptr + m, end, next);
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                // this is for inside entity references
                BT_LT => {
                    *next = ptr;
                    return TOK_INVALID;
                }
                BT_LF => {
                    if ptr == start {
                        *next = ptr + m;
                        return TOK_DATA_NEWLINE;
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                BT_CR => {
                    if ptr == start {
                        ptr += m;
                        if !self.has(ptr, end, 1) {
                            return TOK_TRAILING_CR;
                        }
                        if self.bt(d, ptr) == BT_LF {
                            ptr += m;
                        }
                        *next = ptr;
                        return TOK_DATA_NEWLINE;
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                BT_S => {
                    if ptr == start {
                        *next = ptr + m;
                        return TOK_ATTRIBUTE_VALUE_S;
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                _ => ptr += m,
            }
        }
        *next = ptr;
        TOK_DATA_CHARS
    }

    fn entity_value_tok(&self, d: &[u8], mut ptr: usize, end: usize, next: &mut usize) -> i32 {
        let m = self.m;
        if ptr >= end {
            return TOK_NONE;
        }
        if !self.has(ptr, end, 1) {
            return TOK_PARTIAL;
        }
        let start = ptr;
        while self.has(ptr, end, 1) {
            match self.bt(d, ptr) {
                t @ (BT_LEAD2 | BT_LEAD3 | BT_LEAD4) => ptr += (t - BT_LEAD2 + 2) as usize,
                BT_AMP => {
                    if ptr == start {
                        return self.scan_ref(d, ptr + m, end, next);
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                BT_PERCNT => {
                    if ptr == start {
                        let tok = self.scan_percent(d, ptr + m, end, next);
                        return if tok == TOK_PERCENT { TOK_INVALID } else { tok };
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                BT_LF => {
                    if ptr == start {
                        *next = ptr + m;
                        return TOK_DATA_NEWLINE;
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                BT_CR => {
                    if ptr == start {
                        ptr += m;
                        if !self.has(ptr, end, 1) {
                            return TOK_TRAILING_CR;
                        }
                        if self.bt(d, ptr) == BT_LF {
                            ptr += m;
                        }
                        *next = ptr;
                        return TOK_DATA_NEWLINE;
                    }
                    *next = ptr;
                    return TOK_DATA_CHARS;
                }
                _ => ptr += m,
            }
        }
        *next = ptr;
        TOK_DATA_CHARS
    }

    /// `isPublicId`: the first bad character's position when there is one.
    fn public_id_error(&self, d: &[u8], mut ptr: usize, end: usize) -> Option<usize> {
        ptr += self.m;
        let end = end.saturating_sub(self.m);
        while self.has(ptr, end, 1) {
            let good = match self.bt(d, ptr) {
                BT_DIGIT | BT_HEX | BT_MINUS | BT_APOS | BT_LPAR | BT_RPAR | BT_PLUS | BT_COMMA
                | BT_SOL | BT_EQUALS | BT_QUEST | BT_CR | BT_LF | BT_SEMI | BT_EXCL | BT_AST
                | BT_PERCNT | BT_NUM | BT_COLON => true,
                BT_S => !self.matches(d, ptr, b'\t'),
                t => {
                    let c = self.ascii(d, ptr);
                    (matches!(t, BT_NAME | BT_NMSTRT) && c & !0x7F == 0) || c == 0x24 || c == 0x40
                }
            };
            if !good {
                return Some(ptr);
            }
            ptr += self.m;
        }
        None
    }

    /// `getAtts`, for a start tag the tokenizer has accepted.
    fn get_atts(&self, d: &[u8], mut ptr: usize, atts: &mut Vec<Attribute>) {
        #[derive(PartialEq)]
        enum State {
            Other,
            InName,
            InValue,
        }
        atts.clear();
        let m = self.m;
        let mut state = State::InName;
        let mut open = 0;
        let mut current = Attribute::default();
        ptr += m;
        while ptr < d.len() {
            let t = self.bt(d, ptr);
            match t {
                BT_LEAD2 | BT_LEAD3 | BT_LEAD4 | BT_NONASCII | BT_NMSTRT | BT_HEX => {
                    if state == State::Other {
                        current.name = ptr;
                        current.normalized = true;
                        state = State::InName;
                    }
                    if matches!(t, BT_LEAD2 | BT_LEAD3 | BT_LEAD4) {
                        ptr += (t - BT_LEAD2 + 2) as usize - m;
                    }
                }
                BT_QUOT | BT_APOS => {
                    if state != State::InValue {
                        current.value = ptr + m;
                        state = State::InValue;
                        open = t;
                    } else if open == t {
                        state = State::Other;
                        current.value_end = ptr;
                        atts.push(current);
                    }
                }
                BT_AMP => current.normalized = false,
                BT_S => {
                    if state == State::InName {
                        state = State::Other;
                    } else if state == State::InValue
                        && current.normalized
                        && (ptr == current.value
                            || self.ascii(d, ptr) != 0x20
                            || self.ascii(d, ptr + m) == 0x20
                            || self.bt(d, ptr + m) == open)
                    {
                        current.normalized = false;
                    }
                }
                BT_CR | BT_LF => {
                    if state == State::InName {
                        state = State::Other;
                    } else if state == State::InValue {
                        current.normalized = false;
                    }
                }
                BT_GT | BT_SOL if state != State::InValue => return,
                _ => {}
            }
            ptr += m;
        }
    }

    /// `charRefNumber`, with `ptr` at the `&`.
    fn char_ref_number(&self, d: &[u8], mut ptr: usize) -> i32 {
        let m = self.m;
        let mut result: i32 = 0;
        ptr += 2 * m;
        if self.matches(d, ptr, b'x') {
            ptr += m;
            while ptr < d.len() && !self.matches(d, ptr, b';') {
                let c = self.ascii(d, ptr);
                let digit = match c {
                    0x30..=0x39 => c - 0x30,
                    0x41..=0x46 => 10 + c - 0x41,
                    0x61..=0x66 => 10 + c - 0x61,
                    _ => 0,
                };
                result = (result << 4) + digit;
                if result >= 0x110000 {
                    return -1;
                }
                ptr += m;
            }
        } else {
            while ptr < d.len() && !self.matches(d, ptr, b';') {
                result = result * 10 + (self.ascii(d, ptr) - 0x30);
                if result >= 0x110000 {
                    return -1;
                }
                ptr += m;
            }
        }
        check_char_ref(result)
    }

    /// `predefinedEntityName`.
    fn predefined(&self, d: &[u8], ptr: usize, end: usize) -> Option<u8> {
        let m = self.m;
        let word = |text: &[u8]| {
            text.iter()
                .enumerate()
                .all(|(at, c)| self.matches(d, ptr + at * m, *c))
        };
        match end.saturating_sub(ptr) / m {
            2 if word(b"lt") => Some(b'<'),
            2 if word(b"gt") => Some(b'>'),
            3 if word(b"amp") => Some(b'&'),
            4 if word(b"quot") => Some(b'"'),
            4 if word(b"apos") => Some(b'\''),
            _ => None,
        }
    }

    /// `nameMatchesAscii`.
    fn name_is(&self, d: &[u8], mut ptr: usize, end: usize, name: &[u8]) -> bool {
        for c in name {
            if end.saturating_sub(ptr) < self.m || !self.matches(d, ptr, *c) {
                return false;
            }
            ptr += self.m;
        }
        ptr == end
    }

    /// `nameLength`.
    fn name_length(&self, d: &[u8], start: usize) -> usize {
        let mut ptr = start;
        while ptr < d.len() {
            match self.bt(d, ptr) {
                t @ (BT_LEAD2 | BT_LEAD3 | BT_LEAD4) => ptr += (t - BT_LEAD2 + 2) as usize,
                BT_NONASCII | BT_NMSTRT | BT_COLON | BT_HEX | BT_DIGIT | BT_NAME | BT_MINUS => {
                    ptr += self.m;
                }
                _ => break,
            }
        }
        ptr - start
    }

    /// `updatePosition`.
    fn update_position(
        &self,
        d: &[u8],
        mut ptr: usize,
        end: usize,
        line: &mut u64,
        column: &mut u64,
    ) {
        let m = self.m;
        while self.has(ptr, end, 1) {
            match self.bt(d, ptr) {
                t @ (BT_LEAD2 | BT_LEAD3 | BT_LEAD4) => {
                    ptr += (t - BT_LEAD2 + 2) as usize;
                    *column += 1;
                }
                BT_LF => {
                    *column = 0;
                    *line += 1;
                    ptr += m;
                }
                BT_CR => {
                    *line += 1;
                    ptr += m;
                    if self.has(ptr, end, 1) && self.bt(d, ptr) == BT_LF {
                        ptr += m;
                    }
                    *column = 0;
                }
                _ => {
                    ptr += m;
                    *column += 1;
                }
            }
        }
    }

    /// `XmlConvert` to UTF-8, appending to `out`.
    fn convert(&self, d: &[u8], from: usize, to: usize, out: &mut Vec<u8>) {
        match self.form {
            Form::Utf8 | Form::Ascii => out.extend_from_slice(slice(d, from, to)),
            Form::Latin1 => {
                for &c in slice(d, from, to) {
                    if c & 0x80 != 0 {
                        out.push((c >> 6) | 0xC0);
                        out.push((c & 0x3F) | 0x80);
                    } else {
                        out.push(c);
                    }
                }
            }
            Form::Table => {
                for &c in slice(d, from, to) {
                    let code = self.map[c as usize];
                    if self.types[c as usize] != BT_NONXML && code >= 0 {
                        encode_utf8(code, out);
                    } else {
                        out.push(0);
                    }
                }
            }
            Form::Little2 | Form::Big2 => {
                let to = from + ((to.saturating_sub(from) >> 1) << 1);
                let mut at = from;
                while at < to {
                    let (hi, lo) = self.two(d, at);
                    match hi {
                        0 if lo < 0x80 => out.push(lo),
                        0..=7 => {
                            out.push((lo >> 6) | (hi << 2) | 0xC0);
                            out.push((lo & 0x3F) | 0x80);
                        }
                        0xD8..=0xDB => {
                            if to - at < 4 {
                                return;
                            }
                            let plane = (((hi & 3) << 2) | ((lo >> 6) & 3)) + 1;
                            out.push((plane >> 2) | 0xF0);
                            out.push(((lo >> 2) & 0xF) | ((plane & 3) << 4) | 0x80);
                            at += 2;
                            let (hi2, lo2) = self.two(d, at);
                            out.push(((lo & 3) << 4) | ((hi2 & 3) << 2) | (lo2 >> 6) | 0x80);
                            out.push((lo2 & 0x3F) | 0x80);
                        }
                        _ => {
                            out.push((hi >> 4) | 0xE0);
                            out.push(((hi & 0xF) << 2) | (lo >> 6) | 0x80);
                            out.push((lo & 0x3F) | 0x80);
                        }
                    }
                    at += 2;
                }
            }
        }
    }

    /// `toAscii`: what one byte of output holds, -1 when the next character needs more or there is
    /// none.
    fn to_ascii(&self, d: &[u8], ptr: usize, end: usize) -> i32 {
        if ptr >= end {
            return -1;
        }
        match self.form {
            Form::Utf8 | Form::Latin1 | Form::Table => {
                let c = byte(d, ptr);
                if c < 0x80 { i32::from(c) } else { -1 }
            }
            Form::Ascii => i32::from(byte(d, ptr) as i8),
            Form::Little2 | Form::Big2 => {
                if end - ptr < 2 {
                    return -1;
                }
                let (hi, lo) = self.two(d, ptr);
                if hi == 0 && lo < 0x80 {
                    i32::from(lo)
                } else {
                    -1
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Attribute {
    name: usize,
    value: usize,
    value_end: usize,
    normalized: bool,
}

/// xmlrole.c's handlers. PEs are never expanded here, so only the document entity's states exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handler {
    Prolog0,
    Prolog1,
    Prolog2,
    Doctype0,
    Doctype1,
    Doctype2,
    Doctype3,
    Doctype4,
    Doctype5,
    InternalSubset,
    Entity0,
    Entity1,
    Entity2,
    Entity3,
    Entity4,
    Entity5,
    Entity6,
    Entity7,
    Entity8,
    Entity9,
    Entity10,
    Notation0,
    Notation1,
    Notation2,
    Notation3,
    Notation4,
    Attlist0,
    Attlist1,
    Attlist2,
    Attlist3,
    Attlist4,
    Attlist5,
    Attlist6,
    Attlist7,
    Attlist8,
    Attlist9,
    Element0,
    Element1,
    Element2,
    Element3,
    Element4,
    Element5,
    Element6,
    Element7,
    DeclClose,
    Error,
}

/// The roles that matter here; the rest are `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Error,
    None,
    XmlDecl,
    InstanceStart,
    DoctypeInternalSubset,
    DoctypePublicId,
    DoctypeSystemId,
    DoctypeClose,
    GeneralEntityName,
    ParamEntityName,
    EntityValue,
    EntitySystemId,
    EntityPublicId,
    EntityNotationName,
    NotationPublicId,
    AttlistElementName,
    AttributeName,
    AttributeTypeCdata,
    AttributeTypeId,
    AttributeTypeOther,
    ImpliedAttributeValue,
    RequiredAttributeValue,
    DefaultAttributeValue,
    FixedAttributeValue,
    GroupOpen,
    GroupSequence,
    GroupChoice,
    ParamEntityRef,
}

struct PrologState {
    handler: Handler,
    level: usize,
}

impl PrologState {
    fn common(&mut self) -> Role {
        self.handler = Handler::Error;
        Role::Error
    }

    /// `XmlTokenRole`.
    fn role(&mut self, tok: i32, d: &[u8], ptr: usize, end: usize, enc: &Encoding) -> Role {
        use Handler as H;
        let m = enc.m;
        let name_is = |text: &[u8]| enc.name_is(d, ptr, end, text);
        let decl_is = |text: &[u8]| enc.name_is(d, ptr + 2 * m, end, text);
        let pound_is = |text: &[u8]| enc.name_is(d, ptr + m, end, text);
        match self.handler {
            H::Prolog0 | H::Prolog1 => match tok {
                TOK_PROLOG_S => {
                    self.handler = H::Prolog1;
                    Role::None
                }
                TOK_XML_DECL if self.handler == H::Prolog0 => {
                    self.handler = H::Prolog1;
                    Role::XmlDecl
                }
                TOK_PI | TOK_COMMENT => {
                    self.handler = H::Prolog1;
                    Role::None
                }
                TOK_BOM => Role::None,
                TOK_DECL_OPEN if decl_is(b"DOCTYPE") => {
                    self.handler = H::Doctype0;
                    Role::None
                }
                TOK_INSTANCE_START => {
                    self.handler = H::Error;
                    Role::InstanceStart
                }
                _ => self.common(),
            },
            H::Prolog2 => match tok {
                TOK_PROLOG_S | TOK_PI | TOK_COMMENT => Role::None,
                TOK_INSTANCE_START => {
                    self.handler = H::Error;
                    Role::InstanceStart
                }
                _ => self.common(),
            },
            H::Doctype0 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME | TOK_PREFIXED_NAME => {
                    self.handler = H::Doctype1;
                    Role::None
                }
                _ => self.common(),
            },
            H::Doctype1 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_OPEN_BRACKET => {
                    self.handler = H::InternalSubset;
                    Role::DoctypeInternalSubset
                }
                TOK_DECL_CLOSE => {
                    self.handler = H::Prolog2;
                    Role::DoctypeClose
                }
                TOK_NAME if name_is(b"SYSTEM") => {
                    self.handler = H::Doctype3;
                    Role::None
                }
                TOK_NAME if name_is(b"PUBLIC") => {
                    self.handler = H::Doctype2;
                    Role::None
                }
                _ => self.common(),
            },
            H::Doctype2 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Doctype3;
                    Role::DoctypePublicId
                }
                _ => self.common(),
            },
            H::Doctype3 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Doctype4;
                    Role::DoctypeSystemId
                }
                _ => self.common(),
            },
            H::Doctype4 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_OPEN_BRACKET => {
                    self.handler = H::InternalSubset;
                    Role::DoctypeInternalSubset
                }
                TOK_DECL_CLOSE => {
                    self.handler = H::Prolog2;
                    Role::DoctypeClose
                }
                _ => self.common(),
            },
            H::Doctype5 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_DECL_CLOSE => {
                    self.handler = H::Prolog2;
                    Role::DoctypeClose
                }
                _ => self.common(),
            },
            H::InternalSubset => match tok {
                TOK_PROLOG_S | TOK_PI | TOK_COMMENT | TOK_NONE => Role::None,
                TOK_DECL_OPEN if decl_is(b"ENTITY") => {
                    self.handler = H::Entity0;
                    Role::None
                }
                TOK_DECL_OPEN if decl_is(b"ATTLIST") => {
                    self.handler = H::Attlist0;
                    Role::None
                }
                TOK_DECL_OPEN if decl_is(b"ELEMENT") => {
                    self.handler = H::Element0;
                    Role::None
                }
                TOK_DECL_OPEN if decl_is(b"NOTATION") => {
                    self.handler = H::Notation0;
                    Role::None
                }
                TOK_PARAM_ENTITY_REF => Role::ParamEntityRef,
                TOK_CLOSE_BRACKET => {
                    self.handler = H::Doctype5;
                    Role::None
                }
                _ => self.common(),
            },
            H::Entity0 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_PERCENT => {
                    self.handler = H::Entity1;
                    Role::None
                }
                TOK_NAME => {
                    self.handler = H::Entity2;
                    Role::GeneralEntityName
                }
                _ => self.common(),
            },
            H::Entity1 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME => {
                    self.handler = H::Entity7;
                    Role::ParamEntityName
                }
                _ => self.common(),
            },
            H::Entity2 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME if name_is(b"SYSTEM") => {
                    self.handler = H::Entity4;
                    Role::None
                }
                TOK_NAME if name_is(b"PUBLIC") => {
                    self.handler = H::Entity3;
                    Role::None
                }
                TOK_LITERAL => {
                    self.handler = H::DeclClose;
                    Role::EntityValue
                }
                _ => self.common(),
            },
            H::Entity3 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Entity4;
                    Role::EntityPublicId
                }
                _ => self.common(),
            },
            H::Entity4 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Entity5;
                    Role::EntitySystemId
                }
                _ => self.common(),
            },
            H::Entity5 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_DECL_CLOSE => {
                    self.handler = H::InternalSubset;
                    Role::None
                }
                TOK_NAME if name_is(b"NDATA") => {
                    self.handler = H::Entity6;
                    Role::None
                }
                _ => self.common(),
            },
            H::Entity6 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME => {
                    self.handler = H::DeclClose;
                    Role::EntityNotationName
                }
                _ => self.common(),
            },
            H::Entity7 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME if name_is(b"SYSTEM") => {
                    self.handler = H::Entity9;
                    Role::None
                }
                TOK_NAME if name_is(b"PUBLIC") => {
                    self.handler = H::Entity8;
                    Role::None
                }
                TOK_LITERAL => {
                    self.handler = H::DeclClose;
                    Role::EntityValue
                }
                _ => self.common(),
            },
            H::Entity8 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Entity9;
                    Role::EntityPublicId
                }
                _ => self.common(),
            },
            H::Entity9 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Entity10;
                    Role::EntitySystemId
                }
                _ => self.common(),
            },
            H::Entity10 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_DECL_CLOSE => {
                    self.handler = H::InternalSubset;
                    Role::None
                }
                _ => self.common(),
            },
            H::Notation0 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME => {
                    self.handler = H::Notation1;
                    Role::None
                }
                _ => self.common(),
            },
            H::Notation1 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME if name_is(b"SYSTEM") => {
                    self.handler = H::Notation3;
                    Role::None
                }
                TOK_NAME if name_is(b"PUBLIC") => {
                    self.handler = H::Notation2;
                    Role::None
                }
                _ => self.common(),
            },
            H::Notation2 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Notation4;
                    Role::NotationPublicId
                }
                _ => self.common(),
            },
            H::Notation3 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::DeclClose;
                    Role::None
                }
                _ => self.common(),
            },
            H::Notation4 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::DeclClose;
                    Role::None
                }
                TOK_DECL_CLOSE => {
                    self.handler = H::InternalSubset;
                    Role::None
                }
                _ => self.common(),
            },
            H::Attlist0 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME | TOK_PREFIXED_NAME => {
                    self.handler = H::Attlist1;
                    Role::AttlistElementName
                }
                _ => self.common(),
            },
            H::Attlist1 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_DECL_CLOSE => {
                    self.handler = H::InternalSubset;
                    Role::None
                }
                TOK_NAME | TOK_PREFIXED_NAME => {
                    self.handler = H::Attlist2;
                    Role::AttributeName
                }
                _ => self.common(),
            },
            H::Attlist2 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME if name_is(b"CDATA") => {
                    self.handler = H::Attlist8;
                    Role::AttributeTypeCdata
                }
                TOK_NAME if name_is(b"ID") => {
                    self.handler = H::Attlist8;
                    Role::AttributeTypeId
                }
                TOK_NAME
                    if [
                        &b"IDREF"[..],
                        b"IDREFS",
                        b"ENTITY",
                        b"ENTITIES",
                        b"NMTOKEN",
                        b"NMTOKENS",
                    ]
                    .iter()
                    .any(|text| name_is(text)) =>
                {
                    self.handler = H::Attlist8;
                    Role::AttributeTypeOther
                }
                TOK_NAME if name_is(b"NOTATION") => {
                    self.handler = H::Attlist5;
                    Role::None
                }
                TOK_OPEN_PAREN => {
                    self.handler = H::Attlist3;
                    Role::None
                }
                _ => self.common(),
            },
            H::Attlist3 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NMTOKEN | TOK_NAME | TOK_PREFIXED_NAME => {
                    self.handler = H::Attlist4;
                    Role::None
                }
                _ => self.common(),
            },
            H::Attlist4 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_CLOSE_PAREN => {
                    self.handler = H::Attlist8;
                    Role::None
                }
                TOK_OR => {
                    self.handler = H::Attlist3;
                    Role::None
                }
                _ => self.common(),
            },
            H::Attlist5 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_OPEN_PAREN => {
                    self.handler = H::Attlist6;
                    Role::None
                }
                _ => self.common(),
            },
            H::Attlist6 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME => {
                    self.handler = H::Attlist7;
                    Role::None
                }
                _ => self.common(),
            },
            H::Attlist7 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_CLOSE_PAREN => {
                    self.handler = H::Attlist8;
                    Role::None
                }
                TOK_OR => {
                    self.handler = H::Attlist6;
                    Role::None
                }
                _ => self.common(),
            },
            H::Attlist8 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_POUND_NAME if pound_is(b"IMPLIED") => {
                    self.handler = H::Attlist1;
                    Role::ImpliedAttributeValue
                }
                TOK_POUND_NAME if pound_is(b"REQUIRED") => {
                    self.handler = H::Attlist1;
                    Role::RequiredAttributeValue
                }
                TOK_POUND_NAME if pound_is(b"FIXED") => {
                    self.handler = H::Attlist9;
                    Role::None
                }
                TOK_LITERAL => {
                    self.handler = H::Attlist1;
                    Role::DefaultAttributeValue
                }
                _ => self.common(),
            },
            H::Attlist9 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_LITERAL => {
                    self.handler = H::Attlist1;
                    Role::FixedAttributeValue
                }
                _ => self.common(),
            },
            H::Element0 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME | TOK_PREFIXED_NAME => {
                    self.handler = H::Element1;
                    Role::None
                }
                _ => self.common(),
            },
            H::Element1 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME if name_is(b"EMPTY") || name_is(b"ANY") => {
                    self.handler = H::DeclClose;
                    Role::None
                }
                TOK_OPEN_PAREN => {
                    self.handler = H::Element2;
                    self.level = 1;
                    Role::GroupOpen
                }
                _ => self.common(),
            },
            H::Element2 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_POUND_NAME if pound_is(b"PCDATA") => {
                    self.handler = H::Element3;
                    Role::None
                }
                TOK_OPEN_PAREN => {
                    self.level = 2;
                    self.handler = H::Element6;
                    Role::GroupOpen
                }
                TOK_NAME | TOK_PREFIXED_NAME | TOK_NAME_QUESTION | TOK_NAME_ASTERISK
                | TOK_NAME_PLUS => {
                    self.handler = H::Element7;
                    Role::None
                }
                _ => self.common(),
            },
            H::Element3 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_CLOSE_PAREN | TOK_CLOSE_PAREN_ASTERISK => {
                    self.handler = H::DeclClose;
                    Role::None
                }
                TOK_OR => {
                    self.handler = H::Element4;
                    Role::None
                }
                _ => self.common(),
            },
            H::Element4 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_NAME | TOK_PREFIXED_NAME => {
                    self.handler = H::Element5;
                    Role::None
                }
                _ => self.common(),
            },
            H::Element5 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_CLOSE_PAREN_ASTERISK => {
                    self.handler = H::DeclClose;
                    Role::None
                }
                TOK_OR => {
                    self.handler = H::Element4;
                    Role::None
                }
                _ => self.common(),
            },
            H::Element6 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_OPEN_PAREN => {
                    self.level += 1;
                    Role::GroupOpen
                }
                TOK_NAME | TOK_PREFIXED_NAME | TOK_NAME_QUESTION | TOK_NAME_ASTERISK
                | TOK_NAME_PLUS => {
                    self.handler = H::Element7;
                    Role::None
                }
                _ => self.common(),
            },
            H::Element7 => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_CLOSE_PAREN
                | TOK_CLOSE_PAREN_ASTERISK
                | TOK_CLOSE_PAREN_QUESTION
                | TOK_CLOSE_PAREN_PLUS => {
                    self.level = self.level.saturating_sub(1);
                    if self.level == 0 {
                        self.handler = H::DeclClose;
                    }
                    Role::None
                }
                TOK_COMMA => {
                    self.handler = H::Element6;
                    Role::GroupSequence
                }
                TOK_OR => {
                    self.handler = H::Element6;
                    Role::GroupChoice
                }
                _ => self.common(),
            },
            H::DeclClose => match tok {
                TOK_PROLOG_S => Role::None,
                TOK_DECL_CLOSE => {
                    self.handler = H::InternalSubset;
                    Role::None
                }
                _ => self.common(),
            },
            H::Error => Role::None,
        }
    }
}

/// The result of `doParseXmlDecl`.
#[derive(Default)]
struct XmlDecl {
    encoding_name: Option<usize>,
    new_encoding: Option<NamedEncoding>,
    standalone: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NamedEncoding {
    SameAsDocument,
    Latin1,
    Ascii,
    Utf8,
    Big2,
    Little2,
}

/// A pseudo-attribute, when there was one.
struct Pseudo {
    name: usize,
    name_end: usize,
    value: usize,
}

fn is_space(c: i32) -> bool {
    matches!(c, 0x20 | 0xD | 0xA | 0x9)
}

/// `parsePseudoAttribute`: the attribute and where it ended, or where it went wrong.
fn parse_pseudo(
    enc: &Encoding,
    d: &[u8],
    mut ptr: usize,
    end: usize,
) -> Result<(Option<Pseudo>, usize), usize> {
    let m = enc.m;
    if ptr == end {
        return Ok((None, ptr));
    }
    if !is_space(enc.to_ascii(d, ptr, end)) {
        return Err(ptr);
    }
    loop {
        ptr += m;
        if !is_space(enc.to_ascii(d, ptr, end)) {
            break;
        }
    }
    if ptr == end {
        return Ok((None, ptr));
    }
    let name = ptr;
    let name_end;
    loop {
        let mut c = enc.to_ascii(d, ptr, end);
        if c == -1 {
            return Err(ptr);
        }
        if c == 0x3D {
            name_end = ptr;
            break;
        }
        if is_space(c) {
            name_end = ptr;
            loop {
                ptr += m;
                c = enc.to_ascii(d, ptr, end);
                if !is_space(c) {
                    break;
                }
            }
            if c != 0x3D {
                return Err(ptr);
            }
            break;
        }
        ptr += m;
    }
    if ptr == name {
        return Err(ptr);
    }
    ptr += m;
    let mut c = enc.to_ascii(d, ptr, end);
    while is_space(c) {
        ptr += m;
        c = enc.to_ascii(d, ptr, end);
    }
    if c != 0x22 && c != 0x27 {
        return Err(ptr);
    }
    let open = c;
    ptr += m;
    let value = ptr;
    loop {
        let c = enc.to_ascii(d, ptr, end);
        if c == open {
            break;
        }
        let good = (0x61..=0x7A).contains(&c)
            || (0x41..=0x5A).contains(&c)
            || (0x30..=0x39).contains(&c)
            || c == 0x2E
            || c == 0x2D
            || c == 0x5F;
        if !good {
            return Err(ptr);
        }
        ptr += m;
    }
    Ok((
        Some(Pseudo {
            name,
            name_end,
            value,
        }),
        ptr + m,
    ))
}

/// `findEncoding`.
fn find_encoding(enc: &Encoding, d: &[u8], ptr: usize, end: usize) -> Option<NamedEncoding> {
    let mut name = Vec::new();
    enc.convert(d, ptr, end, &mut name);
    if name.len() > 127 {
        return None;
    }
    if name.eq_ignore_ascii_case(b"UTF-16") && enc.m == 2 {
        return Some(NamedEncoding::SameAsDocument);
    }
    [
        (&b"ISO-8859-1"[..], NamedEncoding::Latin1),
        (b"US-ASCII", NamedEncoding::Ascii),
        (b"UTF-8", NamedEncoding::Utf8),
        (b"UTF-16", NamedEncoding::Big2),
        (b"UTF-16BE", NamedEncoding::Big2),
        (b"UTF-16LE", NamedEncoding::Little2),
    ]
    .iter()
    .find(|(known, _)| name.eq_ignore_ascii_case(known))
    .map(|(_, encoding)| *encoding)
}

/// `doParseXmlDecl` for a document entity: the declaration, or where it went wrong.
fn parse_xml_decl(enc: &Encoding, d: &[u8], ptr: usize, end: usize) -> Result<XmlDecl, usize> {
    let m = enc.m;
    let mut decl = XmlDecl::default();
    let mut ptr = ptr + 5 * m;
    let end = end.saturating_sub(2 * m);
    let (pseudo, after) = parse_pseudo(enc, d, ptr, end)?;
    let Some(mut attribute) = pseudo else {
        return Err(ptr);
    };
    ptr = after;
    if !enc.name_is(d, attribute.name, attribute.name_end, b"version") {
        return Err(attribute.name);
    }
    let value = attribute.value;
    let value_end = ptr - m;
    if value == value_end {
        return Err(value);
    }
    // "1." and digits
    if value_end - value < 2 * m || !enc.name_is(d, value, value + 2 * m, b"1.") {
        return Err(value);
    }
    let mut at = value + 2 * m;
    if at == value_end {
        return Err(value);
    }
    while at != value_end {
        let c = enc.to_ascii(d, at, value_end);
        if !(0x30..=0x39).contains(&c) {
            return Err(value);
        }
        at += m;
    }
    let (pseudo, after) = parse_pseudo(enc, d, ptr, end)?;
    let Some(next) = pseudo else {
        return Ok(decl);
    };
    attribute = next;
    ptr = after;
    if enc.name_is(d, attribute.name, attribute.name_end, b"encoding") {
        let c = enc.to_ascii(d, attribute.value, end);
        if !(0x61..=0x7A).contains(&c) && !(0x41..=0x5A).contains(&c) {
            return Err(attribute.value);
        }
        decl.encoding_name = Some(attribute.value);
        decl.new_encoding = find_encoding(enc, d, attribute.value, ptr - m);
        let (pseudo, after) = parse_pseudo(enc, d, ptr, end)?;
        let Some(next) = pseudo else {
            return Ok(decl);
        };
        attribute = next;
        ptr = after;
    }
    if !enc.name_is(d, attribute.name, attribute.name_end, b"standalone") {
        return Err(attribute.name);
    }
    if enc.name_is(d, attribute.value, ptr - m, b"yes") {
        decl.standalone = true;
    } else if !enc.name_is(d, attribute.value, ptr - m, b"no") {
        return Err(attribute.value);
    }
    while is_space(enc.to_ascii(d, ptr, end)) {
        ptr += m;
    }
    if ptr != end {
        return Err(ptr);
    }
    Ok(decl)
}

/// What each codec does in `PyUnicode_Decode` of all 256 bytes, by normalized name: `P` a page of
/// `crate::codepage`, `M` a map below, `Z` hz, `V` more or fewer than 256 characters, `T` not a text
/// encoding, `I` and `U` a UnicodeError. `!` marks a module name that is not also an alias.
static CODEC_NAMES: &str = "037=P37 1026=P1026 1125=P1125 1140=P1140 1250=P1250 1251=P1251 1252=P1252 1253=P1253 \
    1254=P1254 1255=P1255 1256=P1256 1257=P1257 1258=P1258 273=P273 424=P424 437=P437 500=P500 \
    646=P367 775=P775 850=P850 852=P852 855=P855 857=P857 858=P858 860=P860 861=P861 862=P862 \
    863=P863 864=P864 865=P865 866=P866 869=P869 874=P874 8859=P819 932=V 936=V 949=V 950=V \
    ansi_x3.4_1968=P367 ansi_x3.4_1986=P367 ansi_x3_4_1968=P367 arabic=P708 ascii=P367! \
    asmo_708=P708 base64=T base64_codec=T! base_64=T big5=V! big5_hkscs=V big5_tw=V big5hkscs=V! \
    bz2=T bz2_codec=T! charmap=P819! chinese=V cp00858=P858 cp01140=P1140 cp037=P37! cp1006=P1006! \
    cp1026=P1026! cp1051=P1051 cp1125=P1125! cp1140=P1140! cp1250=P1250! cp1251=P1251! \
    cp1252=P1252! cp1253=P1253! cp1254=P1254! cp1255=P1255! cp1256=P1256! cp1257=P1257! \
    cp1258=P1258! cp1361=V cp154=P154 cp273=P273! cp367=P367 cp424=P424! cp437=P437! cp500=P500! \
    cp65001=P367 cp720=P720! cp737=P737! cp775=P775! cp819=P819 cp850=P850! cp852=P852! \
    cp855=P855! cp856=P856! cp857=P857! cp858=P858! cp860=P860! cp861=P861! cp862=P862! \
    cp863=P863! cp864=P864! cp865=P865! cp866=P866! cp866u=P1125 cp869=P869! cp874=P874! \
    cp875=P875! cp932=V! cp936=V cp949=V! cp950=V! cp_gr=P869 cp_is=P861 csascii=P367 csbig5=V \
    cseuckr=V csibm00858=P858 csibm01140=P1140 csibm037=P37 csibm1026=P1026 csibm273=P273 \
    csibm424=P424 csibm500=P500 csibm855=P855 csibm857=P857 csibm858=P858 csibm860=P860 \
    csibm861=P861 csibm863=P863 csibm864=P864 csibm865=P865 csibm866=P866 csibm869=P869 \
    csiso2022jp=P367 csiso2022kr=V csiso58gb231280=V csisolatin1=P819 csisolatin2=P870 \
    csisolatin3=P28593 csisolatin4=P28594 csisolatin5=P28599 csisolatin6=M1 csisolatinarabic=P708 \
    csisolatincyrillic=P28595 csisolatingreek=P28597 csisolatinhebrew=P10005 cskoi8r=M7 \
    cspc775baltic=P775 cspc850multilingual=P850 cspc862latinhebrew=P862 cspc8codepage437=P437 \
    cspcp852=P852 csptcp154=P154 csshiftjis=V cyrillic=P28595 cyrillic_asian=P154 \
    ebcdic_cp_be=P500 ebcdic_cp_ca=P37 ebcdic_cp_ch=P500 ebcdic_cp_he=P424 ebcdic_cp_nl=P37 \
    ebcdic_cp_us=P37 ebcdic_cp_wt=P37 ebcdic_us_37_euro=P1140 ecma_114=P708 ecma_118=P28597 \
    elot_928=P28597 euc_cn=V euc_jis2004=V euc_jis_2004=V! euc_jisx0213=V! euc_jp=V! euc_kr=V! \
    euccn=V eucgb2312_cn=V eucjis2004=V eucjisx0213=V eucjp=V euckr=V gb18030=V! gb18030_2000=V \
    gb2312=V! gb2312_1980=V gb2312_80=V gbk=V! greek=P28597 greek8=P28597 hebrew=P10005 hex=T \
    hex_codec=T! hkscs=V hp_roman8=P1051! hz=Z! hz_gb=Z hz_gb_2312=Z hzgb=Z ibm00858=P858 \
    ibm01140=P1140 ibm037=P37 ibm039=P37 ibm1026=P1026 ibm1051=P1051 ibm1125=P1125 ibm1140=P1140 \
    ibm273=P273 ibm367=P367 ibm424=P424 ibm437=P437 ibm500=P500 ibm775=P775 ibm819=P819 \
    ibm850=P850 ibm852=P852 ibm855=P855 ibm857=P857 ibm858=P858 ibm860=P860 ibm861=P861 \
    ibm862=P862 ibm863=P863 ibm864=P864 ibm865=P865 ibm866=P866 ibm869=P869 idna=I! \
    iso2022_jp=P367! iso2022_jp_1=P367! iso2022_jp_2=P367! iso2022_jp_2004=P367! \
    iso2022_jp_3=P367! iso2022_jp_ext=P367! iso2022_kr=V! iso2022jp=P367 iso2022jp_1=P367 \
    iso2022jp_2=P367 iso2022jp_2004=P367 iso2022jp_3=P367 iso2022jp_ext=P367 iso2022kr=V \
    iso646_us=P367 iso8859=P819 iso8859_1=P819 iso8859_10=M1! iso8859_11=P10021! \
    iso8859_13=P28603! iso8859_14=M3! iso8859_15=P28605! iso8859_16=M0! iso8859_2=P870! \
    iso8859_3=P28593! iso8859_4=P28594! iso8859_5=P28595! iso8859_6=P708! iso8859_7=P28597! \
    iso8859_8=P10005! iso8859_9=P28599! iso_2022_jp=P367 iso_2022_jp_1=P367 iso_2022_jp_2=P367 \
    iso_2022_jp_2004=P367 iso_2022_jp_3=P367 iso_2022_jp_ext=P367 iso_2022_kr=V \
    iso_646.irv_1991=P367 iso_8859_1=P819 iso_8859_10=M1 iso_8859_10_1992=M1 iso_8859_11=P10021 \
    iso_8859_11_2001=P10021 iso_8859_13=P28603 iso_8859_14=M3 iso_8859_14_1998=M3 \
    iso_8859_15=P28605 iso_8859_16=M0 iso_8859_16_2001=M0 iso_8859_1_1987=P819 iso_8859_2=P870 \
    iso_8859_2_1987=P870 iso_8859_3=P28593 iso_8859_3_1988=P28593 iso_8859_4=P28594 \
    iso_8859_4_1988=P28594 iso_8859_5=P28595 iso_8859_5_1988=P28595 iso_8859_6=P708 \
    iso_8859_6_1987=P708 iso_8859_7=P28597 iso_8859_7_1987=P28597 iso_8859_8=P10005 \
    iso_8859_8_1988=P10005 iso_8859_8_e=P10005 iso_8859_8_i=P10005 iso_8859_9=P28599 \
    iso_8859_9_1989=P28599 iso_celtic=M3 iso_ir_100=P819 iso_ir_101=P870 iso_ir_109=P28593 \
    iso_ir_110=P28594 iso_ir_126=P28597 iso_ir_127=P708 iso_ir_138=P10005 iso_ir_144=P28595 \
    iso_ir_148=P28599 iso_ir_157=M1 iso_ir_166=M2 iso_ir_199=M3 iso_ir_226=M0 iso_ir_58=V \
    iso_ir_6=P367 jisx0213=V johab=V! koi8_r=M7! koi8_t=M6! koi8_u=M8! korean=V ks_c_5601=V \
    ks_c_5601_1987=V ks_x_1001=V ksc5601=V ksx1001=V kz1048=M9! kz_1048=M9 l1=P819 l10=M0 l2=P870 \
    l3=P28593 l4=P28594 l5=P28599 l6=M1 l7=P28603 l8=M3 l9=P28605 latin=P819 latin1=P819 \
    latin10=M0 latin2=P870 latin3=P28593 latin4=P28594 latin5=P28599 latin6=M1 latin7=P28603 \
    latin8=M3 latin9=P28605 latin_1=P819! mac_arabic=P10004! mac_centeuro=P10029 mac_croatian=M10! \
    mac_cyrillic=P10007! mac_farsi=M11! mac_greek=P10006! mac_iceland=P10079! mac_latin2=P10029! \
    mac_roman=P10000! mac_romanian=M5! mac_turkish=P10081! maccentraleurope=P10029 \
    maccyrillic=P10007 macgreek=P10006 maciceland=P10079 macintosh=P10000 maclatin2=P10029 \
    macroman=P10000 macturkish=P10081 ms1361=V ms874=P874 ms932=V ms936=V ms949=V ms950=V \
    ms_kanji=V mskanji=V palmos=M4! pc_multilingual_850_euro=P858 pt154=P154 ptcp154=P154! \
    punycode=V! quopri=T quopri_codec=T! quoted_printable=T quotedprintable=T r8=P1051 \
    raw_unicode_escape=P819! rk1048=M9 roman8=P1051 rot13=T rot_13=T! ruscii=P1125 s_jis=V \
    s_jis_2004=V s_jisx0213=V shift_jis=V! shift_jis_2004=V! shift_jisx0213=V! shiftjis=V \
    shiftjis2004=V shiftjisx0213=V sjis=V sjis_2004=V sjisx0213=V strk1048_2002=M9 thai=P10021 \
    tis620=M2 tis_620=M2! tis_620_0=M2 tis_620_2529_0=M2 tis_620_2529_1=M2 u16=V u32=V u7=V \
    u8=P367 u_jis=V uhc=V ujis=V undefined=U! unicode_1_1_utf_7=V unicode_escape=P819! \
    unicodebigunmarked=V unicodelittleunmarked=V us=P367 us_ascii=P367 utf=P367 utf16=V utf32=V \
    utf7=V utf8=P367 utf8_ucs2=P367 utf8_ucs4=P367 utf_16=V! utf_16_be=V! utf_16_le=V! utf_16be=V \
    utf_16le=V utf_32=V! utf_32_be=V! utf_32_le=V! utf_32be=V utf_32le=V utf_7=V! utf_8=P367! \
    utf_8_sig=P367! uu=T uu_codec=T! windows_1250=P1250 windows_1251=P1251 windows_1252=P1252 \
    windows_1253=P1253 windows_1254=P1254 windows_1255=P1255 windows_1256=P1256 windows_1257=P1257 \
    windows_1258=P1258 windows_31j=V windows_874=P874 x_mac_japanese=V x_mac_korean=V \
    x_mac_simp_chinese=V x_mac_trad_chinese=V zip=T zlib=T zlib_codec=T!";

/// The upper halves of the single-byte codecs that `crate::codepage` has no page for.
static CODEC_MAPS: [&str; 12] = [
    "0080008100820083008400850086008700880089008a008b008c008d008e008f009000910092009300940095\
     0096009700980099009a009b009c009d009e009f00a001040105014120ac201e016000a7016100a9021800ab\
     017900ad017a017b00b000b1010c0142017d201d00b600b7017e010d021900bb015201530178017c00c000c1\
     00c2010200c4010600c600c700c800c900ca00cb00cc00cd00ce00cf0110014300d200d300d4015000d6015a\
     017000d900da00db00dc0118021a00df00e000e100e2010300e4010700e600e700e800e900ea00eb00ec00ed\
     00ee00ef0111014400f200f300f4015100f6015b017100f900fa00fb00fc0119021b00ff",
    "0080008100820083008400850086008700880089008a008b008c008d008e008f009000910092009300940095\
     0096009700980099009a009b009c009d009e009f00a0010401120122012a0128013600a7013b011001600166\
     017d00ad016a014a00b0010501130123012b0129013700b7013c011101610167017e2015016b014b010000c1\
     00c200c300c400c500c6012e010c00c9011800cb011600cd00ce00cf00d00145014c00d300d400d500d60168\
     00d8017200da00db00dc00dd00de00df010100e100e200e300e400e500e6012f010d00e9011900eb011700ed\
     00ee00ef00f00146014d00f300f400f500f6016900f8017300fa00fb00fc00fd00fe0138",
    "0080008100820083008400850086008700880089008a008b008c008d008e008f009000910092009300940095\
     0096009700980099009a009b009c009d009e009ffffd0e010e020e030e040e050e060e070e080e090e0a0e0b\
     0e0c0e0d0e0e0e0f0e100e110e120e130e140e150e160e170e180e190e1a0e1b0e1c0e1d0e1e0e1f0e200e21\
     0e220e230e240e250e260e270e280e290e2a0e2b0e2c0e2d0e2e0e2f0e300e310e320e330e340e350e360e37\
     0e380e390e3afffdfffdfffdfffd0e3f0e400e410e420e430e440e450e460e470e480e490e4a0e4b0e4c0e4d\
     0e4e0e4f0e500e510e520e530e540e550e560e570e580e590e5a0e5bfffdfffdfffdfffd",
    "0080008100820083008400850086008700880089008a008b008c008d008e008f009000910092009300940095\
     0096009700980099009a009b009c009d009e009f00a01e021e0300a3010a010b1e0a00a71e8000a91e821e0b\
     1ef200ad00ae01781e1e1e1f012001211e401e4100b61e561e811e571e831e601ef31e841e851e6100c000c1\
     00c200c300c400c500c600c700c800c900ca00cb00cc00cd00ce00cf017400d100d200d300d400d500d61e6a\
     00d800d900da00db00dc00dd017600df00e000e100e200e300e400e500e600e700e800e900ea00eb00ec00ed\
     00ee00ef017500f100f200f300f400f500f61e6b00f800f900fa00fb00fc00fd017700ff",
    "20ac0081201a0192201e20262020202102c62030016020390152266626632665266020182019201c201d2022\
     2013201402dc21220161203a0153009d009e017800a000a100a200a300a400a500a600a700a800a900aa00ab\
     00ac00ad00ae00af00b000b100b200b300b400b500b600b700b800b900ba00bb00bc00bd00be00bf00c000c1\
     00c200c300c400c500c600c700c800c900ca00cb00cc00cd00ce00cf00d000d100d200d300d400d500d600d7\
     00d800d900da00db00dc00dd00de00df00e000e100e200e300e400e500e600e700e800e900ea00eb00ec00ed\
     00ee00ef00f000f100f200f300f400f500f600f700f800f900fa00fb00fc00fd00fe00ff",
    "00c400c500c700c900d100d600dc00e100e000e200e400e300e500e700e900e800ea00eb00ed00ec00ee00ef\
     00f100f300f200f400f600f500fa00f900fb00fc202000b000a200a300a7202200b600df00ae00a9212200b4\
     00a8226001020218221e00b12264226500a500b522022211220f03c0222b00aa00ba03a90103021900bf00a1\
     00ac221a01922248220600ab00bb202600a000c000c300d50152015320132014201c201d2018201900f725ca\
     00ff0178204420ac2039203a021a021b202100b7201a201e203000c200ca00c100cb00c800cd00ce00cf00cc\
     00d300d4f8ff00d200da00db00d9013102c602dc00af02d802d902da00b802dd02db02c7",
    "049b0493201a0492201e202620202021fffd203004b3203904b204b704b6fffd049a20182019201c201d2022\
     20132014fffd2122fffd203afffdfffdfffdfffdfffd04ef04ee045100a404e300a600a7fffdfffdfffd00ab\
     00ac00ad00aefffd00b000b100b20401fffd04e200b600b7fffd2116fffd00bbfffdfffdfffd00a9044e0430\
     043104460434043504440433044504380439043a043b043c043d043e043f044f044004410442044304360432\
     044c044b04370448044d04490447044a042e0410041104260414041504240413042504180419041a041b041c\
     041d041e041f042f042004210422042304160412042c042b04170428042d04290427042a",
    "25002502250c251025142518251c2524252c2534253c258025842588258c2590259125922593232025a02219\
     221a22482264226500a0232100b000b200b700f725502551255204512553255425552556255725582559255a\
     255b255c255d255e255f25602561040125622563256425652566256725682569256a256b256c00a9044e0430\
     043104460434043504440433044504380439043a043b043c043d043e043f044f044004410442044304360432\
     044c044b04370448044d04490447044a042e0410041104260414041504240413042504180419041a041b041c\
     041d041e041f042f042004210422042304160412042c042b04170428042d04290427042a",
    "25002502250c251025142518251c2524252c2534253c258025842588258c2590259125922593232025a02219\
     221a22482264226500a0232100b000b200b700f725502551255204510454255404560457255725582559255a\
     255b0491255d255e255f25602561040104042563040604072566256725682569256a0490256c00a9044e0430\
     043104460434043504440433044504380439043a043b043c043d043e043f044f044004410442044304360432\
     044c044b04370448044d04490447044a042e0410041104260414041504240413042504180419041a041b041c\
     041d041e041f042f042004210422042304160412042c042b04170428042d04290427042a",
    "04020403201a0453201e20262020202120ac203004092039040a049a04ba040f045220182019201c201d2022\
     20132014fffd21220459203a045a049b04bb045f00a004b004b104d800a404e800a600a7040100a9049200ab\
     00ac00ad00ae04ae00b000b10406045604e900b500b600b704512116049300bb04d904a204a304af04100411\
     04120413041404150416041704180419041a041b041c041d041e041f04200421042204230424042504260427\
     04280429042a042b042c042d042e042f0430043104320433043404350436043704380439043a043b043c043d\
     043e043f0440044104420443044404450446044704480449044a044b044c044d044e044f",
    "00c400c500c700c900d100d600dc00e100e000e200e400e300e500e700e900e800ea00eb00ed00ec00ee00ef\
     00f100f300f200f400f600f500fa00f900fb00fc202000b000a200a300a7202200b600df00ae0160212200b4\
     00a82260017d00d8221e00b122642265220600b522022211220f0161222b00aa00ba03a9017e00f800bf00a1\
     00ac221a01922248010600ab010c202600a000c000c300d50152015301102014201c201d2018201900f725ca\
     f8ff00a9204420ac2039203a00c600bb201300b7201a201e203000c2010700c1010d00c800cd00ce00cf00cc\
     00d300d4011100d200da00db00d9013102c602dc00af03c000cb02da00b800ca00e602c7",
    "00c400a000c700c900d100d600dc00e100e000e200e406ba00ab00e700e900e800ea00eb00ed202600ee00ef\
     00f100f300bb00f400f600f700fa00f900fb00fc00200021002200230024066a0026002700280029002a002b\
     060c002d002e002f06f006f106f206f306f406f506f606f706f806f9003a061b003c003d003e061f274a0621\
     06220623062406250626062706280629062a062b062c062d062e062f06300631063206330634063506360637\
     06380639063a005b005c005d005e005f0640064106420643064406450646064706480649064a064b064c064d\
     064e064f065006510652067e0679068606d506a406af06880691007b007c007d069806d2",
];

/// `PyUnknownEncodingHandler`: `PyUnicode_Decode` of all 256 bytes with 'replace', then the map.
fn unknown_encoding_map(name: &str) -> Result<[i32; 256], PyErr> {
    let unknown = || PyErr::new("LookupError", format!("unknown encoding: {name}"));
    // encodings.normalize_encoding of the lower-cased name, whose characters are ASCII here
    let mut norm = String::with_capacity(name.len());
    let mut punct = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '.' {
            if punct && !norm.is_empty() {
                norm.push('_');
            }
            norm.push(c.to_ascii_lowercase());
            punct = false;
        } else {
            punct = true;
        }
    }
    let find = |key: &str, alias_only: bool| {
        CODEC_NAMES.split_ascii_whitespace().find_map(|entry| {
            let (entry_name, what) = entry.split_once('=')?;
            if entry_name != key {
                return None;
            }
            match what.strip_suffix('!') {
                Some(_) if alias_only => None,
                Some(module) => Some(module),
                None => Some(what),
            }
        })
    };
    let what = find(&norm, false)
        .or_else(|| find(&norm.replace('.', "_"), true))
        .ok_or_else(unknown)?;
    let mut map = [-1i32; 256];
    match what.as_bytes().first() {
        Some(b'V') => Err(PyErr::new(
            "ValueError",
            "multi-byte encodings are not supported",
        )),
        Some(b'T') => Err(PyErr::new(
            "LookupError",
            format!(
                "'{name}' is not a text encoding; use codecs.decode() to handle arbitrary codecs"
            ),
        )),
        Some(b'I') => Err(PyErr::new(
            "UnicodeError",
            "Unsupported error handling: replace",
        )),
        Some(b'U') => Err(PyErr::new("UnicodeError", "undefined encoding")),
        Some(b'Z') => {
            // hz: ASCII except for its escape character
            for (i, slot) in map.iter_mut().enumerate().take(128) {
                *slot = if i == 0x7E { -1 } else { i as i32 };
            }
            Ok(map)
        }
        Some(b'M') => {
            let index: usize = what[1..].parse().map_err(|_| unknown())?;
            let hex = CODEC_MAPS.get(index).ok_or_else(unknown)?;
            for (i, slot) in map.iter_mut().enumerate().take(128) {
                *slot = i as i32;
            }
            for (i, chunk) in hex
                .as_bytes()
                .as_chunks::<4>()
                .0
                .iter()
                .enumerate()
                .take(128)
            {
                let text = std::str::from_utf8(chunk).unwrap_or("fffd");
                let unit = i32::from_str_radix(text, 16).unwrap_or(0xFFFD);
                map[128 + i] = if unit == 0xFFFD { -1 } else { unit };
            }
            Ok(map)
        }
        Some(b'P') => {
            let page: u16 = what[1..].parse().map_err(|_| unknown())?;
            let all: Vec<u8> = (0..=255).collect();
            let text = Decoder::for_codepage(page).decode(&all);
            for (slot, c) in map.iter_mut().zip(text.chars()) {
                *slot = if c == char::REPLACEMENT_CHARACTER {
                    -1
                } else {
                    c as i32
                };
            }
            Ok(map)
        }
        _ => Err(unknown()),
    }
}

/// The billion-laughs limits of expat.
const AMPLIFICATION_THRESHOLD: u64 = 8 * 1024 * 1024;
const MAXIMUM_AMPLIFICATION: f32 = 100.0;
/// The limits of expat's allocation tracker.
const ALLOCATION_THRESHOLD: u64 = 64 * 1024 * 1024;
const MAXIMUM_ALLOCATION_AMPLIFICATION: f32 = 100.0;
/// What this port keeps of entity expansions' text and defaulted attributes before raising
/// `MemoryError`, which Python would at some point: the amplification limit alone allows a hundred
/// times the input, and nothing limits defaulted attributes.
const MAX_EXPANDED: usize = 1 << 30;

/// The block sizes of an expat `STRING_POOL`, for its allocation tracker's sake. Attribute values
/// are the only strings that entities can grow past what the input pays for, so only they run this.
#[derive(Default)]
struct PoolSizes {
    blocks: Vec<u64>,
    free: Vec<u64>,
    start: u64,
}

impl PoolSizes {
    /// `poolGrow` until the current string, `length` long, fits. False for out of memory.
    fn fit(&mut self, length: u64, allocated: &mut u64, direct: u64) -> bool {
        const BLOCK_HEADER: u64 = 12;
        const MALLOC_HEADER: u64 = 16;
        fn tolerable(increase: u64, allocated: u64, direct: u64) -> bool {
            let total = allocated + increase;
            total < ALLOCATION_THRESHOLD
                || total as f32 / direct as f32 <= MAXIMUM_ALLOCATION_AMPLIFICATION
        }
        loop {
            let size = self.blocks.last().copied();
            if let Some(size) = size
                && self.start + length <= size
            {
                return true;
            }
            let space = size.map_or(0, |size| size - self.start);
            if let Some(&free) = self.free.last()
                && (size.is_none() || space < free)
            {
                self.free.pop();
                self.blocks.push(free);
                self.start = 0;
                continue;
            }
            if size.is_some() && self.start == 0 {
                let grown = space * 2;
                if grown > i32::MAX as u64 || !tolerable(grown - space, *allocated, direct) {
                    return false;
                }
                *allocated += grown - space;
                if let Some(last) = self.blocks.last_mut() {
                    *last = grown;
                }
            } else {
                let grown = if space < 1024 { 1024 } else { space * 2 };
                if grown > i32::MAX as u64 {
                    return false;
                }
                let bytes = grown + BLOCK_HEADER + MALLOC_HEADER;
                if !tolerable(bytes, *allocated, direct) {
                    return false;
                }
                *allocated += bytes;
                self.blocks.push(grown);
                self.start = 0;
            }
        }
    }

    /// `poolFinish`, with the terminator in `length`.
    fn finish(&mut self, length: u64) {
        self.start += length;
    }

    /// `poolClear`.
    fn clear(&mut self) {
        if self.free.is_empty() {
            std::mem::swap(&mut self.free, &mut self.blocks);
        } else {
            while let Some(block) = self.blocks.pop() {
                self.free.push(block);
            }
        }
        self.start = 0;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Account {
    Direct,
    EntityExpansion,
    None,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Processor {
    Prolog,
    Content,
    Epilog,
    InternalEntity,
}

#[derive(Default)]
struct Entity {
    text: Option<Rc<[u8]>>,
    processed: usize,
    has_more: bool,
    open: bool,
    notation: bool,
}

struct OpenEntity {
    entity: u32,
    start_tag_level: u32,
}

#[derive(Default)]
struct ElementType {
    prefix: Option<u32>,
    default_atts: Vec<DefaultAttribute>,
    default_for_name: HashMap<u32, usize>,
}

struct DefaultAttribute {
    id: u32,
    value: Option<Rc<[u8]>>,
    is_cdata: bool,
}

struct AttributeId {
    name: Box<[u8]>,
    prefix: Option<u32>,
    xmlns: bool,
    maybe_tokenized: bool,
    /// `name[-1]`: 1 when seen on this tag, 2 when also prefixed.
    flag: u8,
}

struct Prefix {
    /// `None` for the default namespace.
    name: Option<Box<[u8]>>,
    binding: Option<u32>,
}

struct Binding {
    /// With the separator, `}`, at the end.
    uri: Vec<u8>,
    prefix: u32,
    previous: Option<u32>,
}

struct Tag {
    raw_name: usize,
    raw_length: usize,
    bindings: Vec<u32>,
}

/// What `storeAtts` gives the start handler.
struct Started {
    tag: String,
    prefix: Option<String>,
    attrib: Vec<(String, String)>,
}

const XML_NAMESPACE: &[u8] = b"http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE: &[u8] = b"http://www.w3.org/2000/xmlns/";
const NS_SEPARATOR: u8 = b'}';
const DEFAULT_PREFIX: u32 = 0;

fn text_of(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// The first buffer `reportDefault` hands the default handler: converted text comes in up to 1024
/// bytes of whole characters.
fn default_chunk(reference: &[u8], converted: bool) -> &[u8] {
    if !converted || reference.len() <= 1024 {
        return reference;
    }
    let mut end = 1024;
    while end > 0 && reference[end] & 0xC0 == 0x80 {
        end -= 1;
    }
    &reference[..end]
}

/// The `UnicodeDecodeError` of a key cut off inside its last character.
fn truncated_key_error(key: &[u8], at: usize) -> PyErr {
    let left = key.len() - at;
    let message = if left == 1 {
        format!(
            "'utf-8' codec can't decode byte 0x{:02x} in position {at}: unexpected end of data",
            key[at]
        )
    } else {
        format!(
            "'utf-8' codec can't decode bytes in position {at}-{}: unexpected end of data",
            at + left - 1
        )
    };
    PyErr::new("UnicodeDecodeError", message)
}

struct Parser<'a> {
    data: &'a [u8],
    enc: Rc<Encoding>,
    internal: Rc<Encoding>,
    /// `m_encoding` is still the initial scanner.
    initial: bool,
    event_ptr: usize,
    processor: Processor,
    reenter: bool,
    prolog: PrologState,
    tag_level: u32,
    tags: Vec<Tag>,
    open_internal: Vec<OpenEntity>,
    open_attribute: Vec<u32>,
    entity_names: HashMap<Box<[u8]>, u32>,
    entities: Vec<Entity>,
    type_names: HashMap<Box<[u8]>, u32>,
    types: Vec<ElementType>,
    attribute_names: HashMap<Box<[u8]>, u32>,
    attribute_ids: Vec<AttributeId>,
    prefix_names: HashMap<Box<[u8]>, u32>,
    prefixes: Vec<Prefix>,
    bindings: Vec<Binding>,
    free_bindings: Vec<u32>,
    keep_processing: bool,
    standalone: bool,
    has_param_entity_refs: bool,
    decl_entity: Option<u32>,
    decl_element_type: Option<u32>,
    decl_attribute: Option<u32>,
    decl_attribute_is_cdata: bool,
    decl_attribute_is_id: bool,
    group_connector: Vec<u8>,
    count_direct: u64,
    count_indirect: u64,
    expanded: usize,
    allocated: u64,
    temp_pool: PoolSizes,
    dtd_pool: PoolSizes,
    in_dtd_value: bool,
    atts: Vec<Attribute>,
    open: Vec<Element>,
    text_open: bool,
    root: Option<Element>,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Parser<'a> {
        let mut prefix_names = HashMap::new();
        prefix_names.insert(Box::from(&b"xml"[..]), 1);
        let mut xml_uri = XML_NAMESPACE.to_vec();
        xml_uri.push(NS_SEPARATOR);
        Parser {
            data,
            enc: Rc::new(Encoding::new(Form::Utf8, &UTF8_TYPES)),
            internal: Rc::new(Encoding::new(Form::Utf8, &INTERNAL_UTF8_TYPES)),
            initial: true,
            event_ptr: 0,
            processor: Processor::Prolog,
            reenter: false,
            prolog: PrologState {
                handler: Handler::Prolog0,
                level: 0,
            },
            tag_level: 0,
            tags: Vec::new(),
            open_internal: Vec::new(),
            open_attribute: Vec::new(),
            entity_names: HashMap::new(),
            entities: Vec::new(),
            type_names: HashMap::new(),
            types: Vec::new(),
            attribute_names: HashMap::new(),
            attribute_ids: Vec::new(),
            prefix_names,
            prefixes: vec![
                Prefix {
                    name: None,
                    binding: None,
                },
                Prefix {
                    name: Some(Box::from(&b"xml"[..])),
                    binding: Some(0),
                },
            ],
            bindings: vec![Binding {
                uri: xml_uri,
                prefix: 1,
                previous: None,
            }],
            free_bindings: Vec::new(),
            keep_processing: true,
            standalone: false,
            has_param_entity_refs: false,
            decl_entity: None,
            decl_element_type: None,
            decl_attribute: None,
            decl_attribute_is_cdata: false,
            decl_attribute_is_id: false,
            group_connector: Vec::new(),
            count_direct: 0,
            count_indirect: 0,
            expanded: 0,
            allocated: 0,
            temp_pool: PoolSizes::default(),
            dtd_pool: PoolSizes::default(),
            in_dtd_value: false,
            atts: Vec::new(),
            open: Vec::new(),
            text_open: false,
            root: None,
        }
    }

    fn parse(mut self) -> PyResult<Element> {
        match self.run() {
            Ok(()) => match self.root.take() {
                Some(root) => Ok(root),
                None => Err(self.parse_error(XmlError::NoElements.message())),
            },
            Err(Stop::Py(error)) => Err(error),
            Err(Stop::Xml(error)) => Err(self.parse_error(error.message())),
        }
    }

    /// `expat_set_error`, at the position `XML_GetCurrentLineNumber` gives.
    fn parse_error(&self, message: &str) -> PyErr {
        let (mut line, mut column) = (0, 0);
        self.enc
            .update_position(self.data, 0, self.event_ptr, &mut line, &mut column);
        PyErr::new(
            "ParseError",
            format!("{message}: line {}, column {column}", line + 1),
        )
    }

    /// `callProcessor`.
    fn run(&mut self) -> Result<(), Stop> {
        let mut at = 0;
        loop {
            match self.processor {
                Processor::Prolog => at = self.prolog_processor(at)?,
                Processor::Content => at = self.content_processor(at)?,
                Processor::Epilog => at = self.epilog_processor(at)?,
                Processor::InternalEntity => self.internal_entity_processor()?,
            }
            if !self.reenter {
                return Ok(());
            }
            self.reenter = false;
        }
    }

    /// `accountingDiffTolerated`, for a token that has one.
    fn tolerated(&mut self, tok: i32, bytes: usize, account: Account) -> bool {
        if matches!(tok, TOK_INVALID | TOK_PARTIAL | TOK_PARTIAL_CHAR | TOK_NONE)
            || account == Account::None
        {
            return true;
        }
        if account == Account::Direct {
            self.count_direct += bytes as u64;
        } else {
            self.count_indirect += bytes as u64;
        }
        let output = self.count_direct + self.count_indirect;
        if output < AMPLIFICATION_THRESHOLD {
            return true;
        }
        let amplification = if self.count_direct != 0 {
            output as f32 / self.count_direct as f32
        } else {
            let shortest = "<!ENTITY a SYSTEM 'b'>".len() as u64;
            (shortest + self.count_indirect) as f32 / shortest as f32
        };
        amplification <= MAXIMUM_AMPLIFICATION
    }

    fn prolog_processor(&mut self, s: usize) -> Result<usize, Stop> {
        let data = self.data;
        let end = data.len();
        let mut next = s;
        let tok = if self.initial {
            self.init_scan(s, end, &mut next)
        } else {
            self.enc.prolog_tok(data, s, end, &mut next)
        };
        self.do_prolog(s, end, tok, next)
    }

    /// `initScan` for a document entity with no encoding given from outside.
    fn init_scan(&mut self, ptr: usize, end: usize, next: &mut usize) -> i32 {
        let d = self.data;
        if ptr >= end {
            return TOK_NONE;
        }
        if ptr + 1 == end {
            if matches!(d[ptr], 0xFE | 0xFF | 0xEF | 0x00 | 0x3C) {
                return TOK_PARTIAL;
            }
        } else {
            match (d[ptr], d[ptr + 1]) {
                (0xFE, 0xFF) => {
                    *next = ptr + 2;
                    self.set_initial(Form::Big2);
                    return TOK_BOM;
                }
                (0x3C, 0x00) => {
                    self.set_initial(Form::Little2);
                    return self.enc.prolog_tok(d, ptr, end, next);
                }
                (0xFF, 0xFE) => {
                    *next = ptr + 2;
                    self.set_initial(Form::Little2);
                    return TOK_BOM;
                }
                (0xEF, 0xBB) => {
                    if ptr + 2 == end {
                        return TOK_PARTIAL;
                    }
                    if d[ptr + 2] == 0xBF {
                        *next = ptr + 3;
                        self.initial = false;
                        return TOK_BOM;
                    }
                }
                (0, _) => {
                    self.set_initial(Form::Big2);
                    return self.enc.prolog_tok(d, ptr, end, next);
                }
                (_, 0) => {
                    self.set_initial(Form::Little2);
                    return self.enc.prolog_tok(d, ptr, end, next);
                }
                _ => {}
            }
        }
        self.initial = false;
        self.enc.prolog_tok(d, ptr, end, next)
    }

    fn set_initial(&mut self, form: Form) {
        self.initial = false;
        self.enc = Rc::new(Encoding::new(form, &LATIN1_TYPES));
    }

    /// `doProlog`, for the document entity: parameter entities are never expanded.
    fn do_prolog(
        &mut self,
        mut s: usize,
        end: usize,
        mut tok: i32,
        mut next: usize,
    ) -> Result<usize, Stop> {
        let d = self.data;
        let mut enc = Rc::clone(&self.enc);
        loop {
            self.event_ptr = s;
            if tok <= 0 {
                match tok {
                    TOK_INVALID => {
                        self.event_ptr = next;
                        return Err(XmlError::InvalidToken.into());
                    }
                    TOK_PARTIAL => return Err(XmlError::UnclosedToken.into()),
                    TOK_PARTIAL_CHAR => return Err(XmlError::PartialChar.into()),
                    TOK_NONE => return Err(XmlError::NoElements.into()),
                    t if t == -TOK_PROLOG_S => tok = -tok,
                    _ => {
                        tok = -tok;
                        next = end;
                    }
                }
            }
            let role = self.prolog.role(tok, d, s, next, &enc);
            if !matches!(role, Role::InstanceStart | Role::XmlDecl)
                && !self.tolerated(tok, next - s, Account::Direct)
            {
                return Err(XmlError::AmplificationLimitBreach.into());
            }
            let m = enc.m;
            match role {
                Role::XmlDecl => {
                    self.process_xml_decl(s, next)?;
                    enc = Rc::clone(&self.enc);
                }
                Role::DoctypePublicId => {
                    self.decl_entity = None;
                    self.has_param_entity_refs = true;
                    self.check_public_id(&enc, s, next)?;
                }
                Role::EntityPublicId | Role::NotationPublicId => {
                    self.check_public_id(&enc, s, next)?;
                }
                Role::DoctypeSystemId => self.has_param_entity_refs = true,
                Role::InstanceStart => {
                    self.processor = Processor::Content;
                    return self.content_processor(s);
                }
                Role::AttlistElementName => {
                    let name = self.stored(&enc, d, s, next);
                    self.decl_element_type = Some(self.element_type(&name));
                }
                Role::AttributeName => {
                    self.decl_attribute = Some(self.attribute_id(&enc, d, s, next));
                    self.decl_attribute_is_cdata = false;
                    self.decl_attribute_is_id = false;
                }
                Role::AttributeTypeCdata => self.decl_attribute_is_cdata = true,
                Role::AttributeTypeId => self.decl_attribute_is_id = true,
                Role::ImpliedAttributeValue | Role::RequiredAttributeValue => {
                    if self.keep_processing {
                        self.define_attribute(self.decl_attribute_is_id, None);
                    }
                }
                Role::DefaultAttributeValue | Role::FixedAttributeValue => {
                    if self.keep_processing {
                        self.in_dtd_value = true;
                        let value = self.store_attribute_value(
                            &enc,
                            d,
                            true,
                            self.decl_attribute_is_cdata,
                            s + m,
                            next - m,
                            Account::None,
                        )?;
                        self.in_dtd_value = false;
                        self.define_attribute(false, Some(Rc::from(value)));
                    }
                }
                Role::EntityValue => {
                    if self.keep_processing {
                        let (value, result) = self.store_entity_value(&enc, s + m, next - m);
                        if let Some(entity) = self.decl_entity {
                            self.entities[entity as usize].text = Some(Rc::from(value));
                        }
                        result?;
                    }
                }
                Role::GeneralEntityName => {
                    if enc.predefined(d, s, next).is_some() {
                        self.decl_entity = None;
                    } else if self.keep_processing {
                        let name = self.stored(&enc, d, s, next);
                        self.decl_entity = if self.entity_names.contains_key(name.as_slice()) {
                            None
                        } else {
                            let index = self.entities.len() as u32;
                            self.entity_names.insert(name.into_boxed_slice(), index);
                            self.entities.push(Entity::default());
                            Some(index)
                        };
                    } else {
                        self.decl_entity = None;
                    }
                }
                // nothing can use a parameter entity's declaration without PE parsing
                Role::ParamEntityName => self.decl_entity = None,
                Role::EntityNotationName => {
                    if self.keep_processing
                        && let Some(entity) = self.decl_entity
                    {
                        self.entities[entity as usize].notation = true;
                    }
                }
                Role::Error => {
                    return Err(match tok {
                        TOK_PARAM_ENTITY_REF => XmlError::ParamEntityRef,
                        TOK_XML_DECL => XmlError::MisplacedXmlPi,
                        _ => XmlError::Syntax,
                    }
                    .into());
                }
                Role::GroupOpen => {
                    let level = self.prolog.level;
                    if level >= self.group_connector.len() {
                        self.group_connector.resize(level + 1, 0);
                    }
                    self.group_connector[level] = 0;
                }
                Role::GroupSequence | Role::GroupChoice => {
                    let level = self.prolog.level;
                    if level >= self.group_connector.len() {
                        self.group_connector.resize(level + 1, 0);
                    }
                    let (other, mine) = if role == Role::GroupSequence {
                        (b'|', b',')
                    } else {
                        (b',', b'|')
                    };
                    if self.group_connector[level] == other {
                        return Err(XmlError::Syntax.into());
                    }
                    self.group_connector[level] = mine;
                }
                Role::ParamEntityRef => {
                    self.has_param_entity_refs = true;
                    self.keep_processing = self.standalone;
                }
                // an external entity's text stays None
                Role::EntitySystemId
                | Role::DoctypeInternalSubset
                | Role::DoctypeClose
                | Role::AttributeTypeOther
                | Role::None => {}
            }
            s = next;
            tok = enc.prolog_tok(d, s, end, &mut next);
        }
    }

    fn check_public_id(&mut self, enc: &Encoding, s: usize, next: usize) -> Result<(), Stop> {
        if let Some(bad) = enc.public_id_error(self.data, s, next) {
            self.event_ptr = bad;
            return Err(XmlError::PublicId.into());
        }
        Ok(())
    }

    /// `processXmlDecl`.
    fn process_xml_decl(&mut self, s: usize, next: usize) -> Result<(), Stop> {
        if !self.tolerated(TOK_XML_DECL, next - s, Account::Direct) {
            return Err(XmlError::AmplificationLimitBreach.into());
        }
        let d = self.data;
        let enc = Rc::clone(&self.enc);
        let decl = match parse_xml_decl(&enc, d, s, next) {
            Ok(decl) => decl,
            Err(bad) => {
                self.event_ptr = bad;
                return Err(XmlError::XmlDecl.into());
            }
        };
        if decl.standalone {
            self.standalone = true;
        }
        if let Some(named) = decl.new_encoding {
            let min = match named {
                NamedEncoding::SameAsDocument | NamedEncoding::Big2 | NamedEncoding::Little2 => 2,
                _ => 1,
            };
            let same_two = match named {
                NamedEncoding::SameAsDocument => true,
                NamedEncoding::Big2 => enc.form == Form::Big2,
                NamedEncoding::Little2 => enc.form == Form::Little2,
                _ => true,
            };
            if min != enc.m || !same_two {
                self.event_ptr = decl.encoding_name.unwrap_or(s);
                return Err(XmlError::IncorrectEncoding.into());
            }
            match named {
                NamedEncoding::Latin1 => {
                    self.enc = Rc::new(Encoding::new(Form::Latin1, &LATIN1_TYPES));
                }
                NamedEncoding::Ascii => {
                    self.enc = Rc::new(Encoding::new(Form::Ascii, &ASCII_TYPES));
                }
                NamedEncoding::Utf8 => {
                    self.enc = Rc::new(Encoding::new(Form::Utf8, &UTF8_TYPES));
                }
                _ => {}
            }
        } else if let Some(at) = decl.encoding_name {
            let length = enc.name_length(d, at);
            let mut name = Vec::new();
            enc.convert(d, at, at + length, &mut name);
            let name = text_of(name);
            let map = unknown_encoding_map(&name).map_err(Stop::Py)?;
            match Encoding::unknown(&map) {
                Some(unknown) => self.enc = Rc::new(unknown),
                None => {
                    self.event_ptr = at;
                    return Err(XmlError::UnknownEncoding.into());
                }
            }
        }
        Ok(())
    }

    fn stored(&self, enc: &Encoding, d: &[u8], from: usize, to: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(to.saturating_sub(from));
        enc.convert(d, from, to, &mut out);
        out
    }

    fn prefix_for(&mut self, name: &[u8]) -> u32 {
        if let Some(prefix) = self.prefix_names.get(name) {
            return *prefix;
        }
        let index = self.prefixes.len() as u32;
        self.prefix_names.insert(Box::from(name), index);
        self.prefixes.push(Prefix {
            name: Some(Box::from(name)),
            binding: None,
        });
        index
    }

    /// `getElementType`, with `setElementTypePrefix` for a new one.
    fn element_type(&mut self, name: &[u8]) -> u32 {
        if let Some(index) = self.type_names.get(name) {
            return *index;
        }
        let prefix = name
            .iter()
            .position(|c| *c == b':')
            .map(|colon| self.prefix_for(&name[..colon]));
        let index = self.types.len() as u32;
        self.type_names.insert(Box::from(name), index);
        self.types.push(ElementType {
            prefix,
            ..ElementType::default()
        });
        index
    }

    /// `getAttributeId`.
    fn attribute_id(&mut self, enc: &Encoding, d: &[u8], from: usize, to: usize) -> u32 {
        let converted;
        let name: &[u8] = if matches!(enc.form, Form::Utf8 | Form::Ascii) {
            slice(d, from, to)
        } else {
            converted = self.stored(enc, d, from, to);
            &converted
        };
        if let Some(index) = self.attribute_names.get(name) {
            return *index;
        }
        let (prefix, xmlns) = if name == b"xmlns" {
            (Some(DEFAULT_PREFIX), true)
        } else if let Some(rest) = name.strip_prefix(b"xmlns:") {
            (Some(self.prefix_for(rest)), true)
        } else {
            // attributes without prefix are not in the default namespace
            let prefix = name
                .iter()
                .position(|c| *c == b':')
                .map(|colon| self.prefix_for(&name[..colon]));
            (prefix, false)
        };
        let index = self.attribute_ids.len() as u32;
        self.attribute_names.insert(Box::from(name), index);
        self.attribute_ids.push(AttributeId {
            name: Box::from(name),
            prefix,
            xmlns,
            maybe_tokenized: false,
            flag: 0,
        });
        index
    }

    /// `defineAttribute`, on the declaration in hand.
    fn define_attribute(&mut self, is_id: bool, value: Option<Rc<[u8]>>) {
        let (Some(element), Some(id)) = (self.decl_element_type, self.decl_attribute) else {
            return;
        };
        let is_cdata = self.decl_attribute_is_cdata;
        let element = &mut self.types[element as usize];
        if (value.is_some() || is_id) && element.default_for_name.contains_key(&id) {
            return;
        }
        let at = element.default_atts.len();
        element.default_atts.push(DefaultAttribute {
            id,
            value,
            is_cdata,
        });
        if !is_cdata {
            self.attribute_ids[id as usize].maybe_tokenized = true;
        }
        element.default_for_name.entry(id).or_insert(at);
    }

    /// `storeEntityValue`, for a literal in the document entity. The value so far comes back even
    /// when there's an error.
    fn store_entity_value(
        &mut self,
        enc: &Encoding,
        from: usize,
        to: usize,
    ) -> (Vec<u8>, Result<(), Stop>) {
        let d = self.data;
        let mut value = Vec::new();
        let mut ptr = from;
        if ptr >= to {
            return (value, Ok(()));
        }
        loop {
            let mut next = ptr;
            let tok = enc.entity_value_tok(d, ptr, to, &mut next);
            if !self.tolerated(tok, next - ptr, Account::None) {
                return (value, Err(XmlError::AmplificationLimitBreach.into()));
            }
            match tok {
                TOK_PARAM_ENTITY_REF => {
                    // in the internal subset, PE references aren't legal within declarations
                    self.event_ptr = ptr;
                    return (value, Err(XmlError::ParamEntityRef.into()));
                }
                TOK_NONE => return (value, Ok(())),
                TOK_ENTITY_REF | TOK_DATA_CHARS => enc.convert(d, ptr, next, &mut value),
                TOK_TRAILING_CR => {
                    next = ptr + enc.m;
                    value.push(0xA);
                }
                TOK_DATA_NEWLINE => value.push(0xA),
                TOK_CHAR_REF => {
                    let n = enc.char_ref_number(d, ptr);
                    if n < 0 {
                        self.event_ptr = ptr;
                        return (value, Err(XmlError::BadCharRef.into()));
                    }
                    encode_utf8(n, &mut value);
                }
                TOK_PARTIAL => {
                    self.event_ptr = ptr;
                    return (value, Err(XmlError::InvalidToken.into()));
                }
                _ => {
                    // TOK_INVALID, and TOK_PARTIAL_CHAR can't get here on checked text
                    self.event_ptr = next;
                    return (value, Err(XmlError::InvalidToken.into()));
                }
            }
            ptr = next;
        }
    }

    /// `storeAttributeValue` with `appendAttributeValue`, whose open entities are kept on a stack.
    #[allow(clippy::too_many_arguments)]
    fn store_attribute_value(
        &mut self,
        enc: &Encoding,
        d: &[u8],
        is_main: bool,
        is_cdata: bool,
        from: usize,
        to: usize,
        account: Account,
    ) -> Result<Vec<u8>, Stop> {
        let mut pool = Vec::new();
        let mut next = from;
        let internal = Rc::clone(&self.internal);
        loop {
            match self.open_attribute.last().copied() {
                None => {
                    next = self.append_attribute_value(
                        enc, d, is_main, is_cdata, next, to, &mut pool, account,
                    )?;
                }
                Some(entity) => {
                    let current = &self.entities[entity as usize];
                    if current.has_more {
                        let text = current.text.clone().unwrap_or_else(|| Rc::from(&b""[..]));
                        let start = current.processed;
                        let after = self.append_attribute_value(
                            &internal,
                            &text,
                            false,
                            is_cdata,
                            start,
                            text.len(),
                            &mut pool,
                            Account::EntityExpansion,
                        )?;
                        let current = &mut self.entities[entity as usize];
                        if after < text.len() {
                            current.processed = after;
                        } else {
                            current.has_more = false;
                        }
                        continue;
                    }
                    self.entities[entity as usize].open = false;
                    self.open_attribute.pop();
                }
            }
            if self.open_attribute.is_empty() && next == to {
                break;
            }
        }
        if !is_cdata && pool.last() == Some(&0x20) {
            pool.pop();
        }
        self.finish_value(pool.len())?;
        Ok(pool)
    }

    /// Whether the pool of the value in hand can grow to `length`, for the allocation tracker.
    fn value_fits(&mut self, length: usize) -> Result<(), Stop> {
        let pool = if self.in_dtd_value {
            &mut self.dtd_pool
        } else {
            &mut self.temp_pool
        };
        if pool.fit(length as u64, &mut self.allocated, self.count_direct) {
            Ok(())
        } else {
            Err(XmlError::NoMemory.into())
        }
    }

    /// The terminator of a value, and `poolFinish`.
    fn finish_value(&mut self, length: usize) -> Result<(), Stop> {
        self.value_fits(length + 1)?;
        let pool = if self.in_dtd_value {
            &mut self.dtd_pool
        } else {
            &mut self.temp_pool
        };
        pool.finish(length as u64 + 1);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn append_attribute_value(
        &mut self,
        enc: &Encoding,
        d: &[u8],
        is_main: bool,
        is_cdata: bool,
        mut ptr: usize,
        end: usize,
        pool: &mut Vec<u8>,
        account: Account,
    ) -> Result<usize, Stop> {
        loop {
            let mut next = ptr;
            let tok = enc.attribute_value_tok(d, ptr, end, &mut next);
            if !self.tolerated(tok, next - ptr, account) {
                return Err(XmlError::AmplificationLimitBreach.into());
            }
            match tok {
                TOK_NONE => return Ok(next),
                TOK_INVALID => {
                    if is_main {
                        self.event_ptr = next;
                    }
                    return Err(XmlError::InvalidToken.into());
                }
                TOK_PARTIAL => {
                    if is_main {
                        self.event_ptr = ptr;
                    }
                    return Err(XmlError::InvalidToken.into());
                }
                TOK_CHAR_REF => {
                    let n = enc.char_ref_number(d, ptr);
                    if n < 0 {
                        if is_main {
                            self.event_ptr = ptr;
                        }
                        return Err(XmlError::BadCharRef.into());
                    }
                    if !(!is_cdata && n == 0x20 && (pool.is_empty() || pool.last() == Some(&0x20)))
                    {
                        encode_utf8(n, pool);
                    }
                }
                TOK_DATA_CHARS => enc.convert(d, ptr, next, pool),
                TOK_TRAILING_CR | TOK_ATTRIBUTE_VALUE_S | TOK_DATA_NEWLINE => {
                    if tok == TOK_TRAILING_CR {
                        next = ptr + enc.m;
                    }
                    if is_cdata || !(pool.is_empty() || pool.last() == Some(&0x20)) {
                        pool.push(0x20);
                    }
                }
                TOK_ENTITY_REF => {
                    let m = enc.m;
                    if let Some(ch) = enc.predefined(d, ptr + m, next - m) {
                        self.tolerated(tok, 1, Account::EntityExpansion);
                        pool.push(ch);
                    } else {
                        let name = self.stored(enc, d, ptr + m, next - m);
                        let entity = self.entity_names.get(name.as_slice()).copied();
                        let check = !self.has_param_entity_refs || self.standalone;
                        let Some(entity) = entity else {
                            if check {
                                return Err(XmlError::UndefinedEntity.into());
                            }
                            ptr = next;
                            continue;
                        };
                        let target = &self.entities[entity as usize];
                        if target.open {
                            if is_main {
                                self.event_ptr = ptr;
                            }
                            return Err(XmlError::RecursiveEntityRef.into());
                        }
                        if target.notation {
                            if is_main {
                                self.event_ptr = ptr;
                            }
                            return Err(XmlError::BinaryEntityRef.into());
                        }
                        if target.text.is_none() {
                            if is_main {
                                self.event_ptr = ptr;
                            }
                            return Err(XmlError::AttributeExternalEntityRef.into());
                        }
                        let target = &mut self.entities[entity as usize];
                        target.open = true;
                        target.has_more = true;
                        target.processed = 0;
                        self.open_attribute.push(entity);
                        return Ok(next);
                    }
                }
                _ => {
                    if is_main {
                        self.event_ptr = ptr;
                    }
                    return Err(XmlError::InvalidToken.into());
                }
            }
            self.value_fits(pool.len())?;
            ptr = next;
        }
    }

    fn content_processor(&mut self, start: usize) -> Result<usize, Stop> {
        let enc = Rc::clone(&self.enc);
        let data = self.data;
        self.do_content(0, &enc, data, true, start, data.len(), Account::Direct)
    }

    /// `internalEntityProcessor`.
    fn internal_entity_processor(&mut self) -> Result<(), Stop> {
        let Some(open) = self.open_internal.last() else {
            return Ok(());
        };
        let (index, start_tag_level) = (open.entity as usize, open.start_tag_level);
        if self.entities[index].has_more {
            let text = self.entities[index]
                .text
                .clone()
                .unwrap_or_else(|| Rc::from(&b""[..]));
            let start = self.entities[index].processed;
            let internal = Rc::clone(&self.internal);
            let next = self.do_content(
                start_tag_level,
                &internal,
                &text,
                false,
                start,
                text.len(),
                Account::EntityExpansion,
            )?;
            if next != text.len() && self.reenter {
                self.entities[index].processed = next;
                return Ok(());
            }
            self.entities[index].has_more = false;
            if start_tag_level != self.tag_level {
                return Err(XmlError::AsyncEntity.into());
            }
            self.reenter = true;
            return Ok(());
        }
        self.entities[index].open = false;
        self.open_internal.pop();
        if self.open_internal.is_empty() {
            self.processor = Processor::Content;
        }
        self.reenter = true;
        Ok(())
    }

    /// `expat_data_handler` and `treebuilder_handle_data`: only the text before a first child stays.
    fn on_data(
        &mut self,
        enc: &Encoding,
        d: &[u8],
        from: usize,
        to: usize,
        is_main: bool,
    ) -> Result<(), Stop> {
        if !self.text_open {
            return Ok(());
        }
        if !is_main {
            self.expanded += to.saturating_sub(from);
            if self.expanded > MAX_EXPANDED {
                return Err(Stop::Py(memory_error()));
            }
        }
        let Some(top) = self.open.last_mut() else {
            return Ok(());
        };
        let text = top.text.get_or_insert_with(String::new);
        if matches!(enc.form, Form::Utf8 | Form::Ascii) {
            text.push_str(&String::from_utf8_lossy(slice(d, from, to)));
        } else {
            let mut out = Vec::with_capacity(to.saturating_sub(from));
            enc.convert(d, from, to, &mut out);
            text.push_str(&String::from_utf8_lossy(&out));
        }
        Ok(())
    }

    fn on_char(&mut self, c: i32) {
        if !self.text_open {
            return;
        }
        if let Some(top) = self.open.last_mut() {
            let mut out = Vec::with_capacity(4);
            encode_utf8(c, &mut out);
            top.text
                .get_or_insert_with(String::new)
                .push_str(&String::from_utf8_lossy(&out));
        }
    }

    fn on_start(&mut self, started: Started) {
        self.open.push(Element {
            tag: started.tag,
            prefix: started.prefix,
            attrib: started.attrib,
            text: None,
            children: Vec::new(),
        });
        self.text_open = true;
    }

    fn on_end(&mut self) {
        self.text_open = false;
        let Some(done) = self.open.pop() else {
            return;
        };
        match self.open.last_mut() {
            Some(parent) => {
                if parent.children.capacity() == 0 {
                    parent.children.reserve_exact(1);
                }
                parent.children.push(done);
            }
            None => self.root = Some(done),
        }
    }

    /// `doContent`. `d` is the document or an entity's text, and `is_main` says which: only the
    /// document's tokens move the error position.
    #[allow(clippy::too_many_arguments)]
    fn do_content(
        &mut self,
        start_tag_level: u32,
        enc: &Rc<Encoding>,
        d: &[u8],
        is_main: bool,
        mut s: usize,
        end: usize,
        account: Account,
    ) -> Result<usize, Stop> {
        let m = enc.m;
        if is_main {
            self.event_ptr = s;
        }
        loop {
            let mut next = s;
            let tok = enc.content_tok(d, s, end, &mut next);
            let after = if tok == TOK_TRAILING_RSQB || tok == TOK_TRAILING_CR {
                end
            } else {
                next
            };
            if !self.tolerated(tok, after - s, account) {
                return Err(XmlError::AmplificationLimitBreach.into());
            }
            match tok {
                TOK_TRAILING_CR => {
                    self.on_char(0xA);
                    if start_tag_level == 0 {
                        return Err(XmlError::NoElements.into());
                    }
                    if self.tag_level != start_tag_level {
                        return Err(XmlError::AsyncEntity.into());
                    }
                    return Ok(end);
                }
                TOK_NONE => {
                    if start_tag_level > 0 {
                        if self.tag_level != start_tag_level {
                            return Err(XmlError::AsyncEntity.into());
                        }
                        return Ok(s);
                    }
                    return Err(XmlError::NoElements.into());
                }
                TOK_INVALID => {
                    if is_main {
                        self.event_ptr = next;
                    }
                    return Err(XmlError::InvalidToken.into());
                }
                TOK_PARTIAL => return Err(XmlError::UnclosedToken.into()),
                TOK_PARTIAL_CHAR => return Err(XmlError::PartialChar.into()),
                TOK_ENTITY_REF => {
                    if let Some(ch) = enc.predefined(d, s + m, next - m) {
                        self.tolerated(tok, 1, Account::EntityExpansion);
                        self.on_char(i32::from(ch));
                    } else {
                        self.entity_ref(enc, d, s, next)?;
                    }
                }
                TOK_START_TAG_NO_ATTS | TOK_START_TAG_WITH_ATTS => {
                    let raw_name = s + m;
                    let raw_length = enc.name_length(d, raw_name);
                    self.tag_level += 1;
                    let name = self.stored(enc, d, raw_name, raw_name + raw_length);
                    let mut bindings = Vec::new();
                    let started =
                        self.store_atts(enc, d, is_main, s, &name, &mut bindings, account)?;
                    self.tags.push(Tag {
                        raw_name,
                        raw_length,
                        bindings,
                    });
                    self.temp_pool.clear();
                    self.on_start(started);
                }
                TOK_EMPTY_ELEMENT_NO_ATTS | TOK_EMPTY_ELEMENT_WITH_ATTS => {
                    let raw_name = s + m;
                    let raw_length = enc.name_length(d, raw_name);
                    let name = self.stored(enc, d, raw_name, raw_name + raw_length);
                    let mut bindings = Vec::new();
                    self.finish_value(name.len())?;
                    let started =
                        self.store_atts(enc, d, is_main, s, &name, &mut bindings, Account::None)?;
                    self.temp_pool.clear();
                    self.on_start(started);
                    if is_main {
                        self.event_ptr = next;
                    }
                    self.on_end();
                    self.release_bindings(&bindings);
                    if self.tag_level == 0 {
                        return self.epilog_processor(next);
                    }
                }
                TOK_END_TAG => {
                    if self.tag_level == start_tag_level {
                        return Err(XmlError::AsyncEntity.into());
                    }
                    let raw_name = s + 2 * m;
                    let length = enc.name_length(d, raw_name);
                    let Some(tag) = self.tags.last() else {
                        return Err(XmlError::AsyncEntity.into());
                    };
                    if length != tag.raw_length
                        || slice(d, tag.raw_name, tag.raw_name + length)
                            != slice(d, raw_name, raw_name + length)
                    {
                        if is_main {
                            self.event_ptr = raw_name;
                        }
                        return Err(XmlError::TagMismatch.into());
                    }
                    self.tag_level -= 1;
                    self.on_end();
                    if let Some(tag) = self.tags.pop() {
                        self.release_bindings(&tag.bindings);
                    }
                    if self.tag_level == 0 {
                        return self.epilog_processor(next);
                    }
                }
                TOK_CHAR_REF => {
                    let n = enc.char_ref_number(d, s);
                    if n < 0 {
                        return Err(XmlError::BadCharRef.into());
                    }
                    self.on_char(n);
                }
                TOK_XML_DECL => return Err(XmlError::MisplacedXmlPi.into()),
                TOK_DATA_NEWLINE => self.on_char(0xA),
                TOK_CDATA_SECT_OPEN => {
                    next = self.do_cdata_section(enc, d, is_main, next, end, account)?;
                }
                TOK_TRAILING_RSQB => {
                    self.on_data(enc, d, s, end, is_main)?;
                    if start_tag_level == 0 {
                        if is_main {
                            self.event_ptr = end;
                        }
                        return Err(XmlError::NoElements.into());
                    }
                    if self.tag_level != start_tag_level {
                        if is_main {
                            self.event_ptr = end;
                        }
                        return Err(XmlError::AsyncEntity.into());
                    }
                    return Ok(end);
                }
                TOK_DATA_CHARS => self.on_data(enc, d, s, next, is_main)?,
                _ => {}
            }
            if self.reenter {
                return Ok(next);
            }
            if is_main {
                self.event_ptr = next;
            }
            s = next;
        }
    }

    /// A reference to anything but a predefined entity, in content.
    fn entity_ref(
        &mut self,
        enc: &Rc<Encoding>,
        d: &[u8],
        s: usize,
        next: usize,
    ) -> Result<(), Stop> {
        let m = enc.m;
        let name = self.stored(enc, d, s + m, next - m);
        let entity = self.entity_names.get(name.as_slice()).copied();
        // what expat_default_handler does with a reference, for the dict of entities it has none of
        let undefined = |parser: &Parser, enc: &Rc<Encoding>| {
            let reference = parser.stored(enc, d, s, next);
            let chunk = default_chunk(&reference, !matches!(enc.form, Form::Utf8 | Form::Ascii));
            let key = chunk.get(1..chunk.len().saturating_sub(1)).unwrap_or(&[]);
            if let Err(error) = std::str::from_utf8(key) {
                return truncated_key_error(key, error.valid_up_to());
            }
            let shown = &chunk[..chunk.len().min(100)];
            parser.parse_error(&format!(
                "undefined entity {}",
                String::from_utf8_lossy(shown)
            ))
        };
        let Some(entity) = entity else {
            if !self.has_param_entity_refs || self.standalone {
                return Err(XmlError::UndefinedEntity.into());
            }
            return Err(Stop::Py(undefined(self, enc)));
        };
        let target = &self.entities[entity as usize];
        if target.open {
            return Err(XmlError::RecursiveEntityRef.into());
        }
        if target.notation {
            return Err(XmlError::BinaryEntityRef.into());
        }
        if target.text.is_none() {
            return Err(Stop::Py(undefined(self, enc)));
        }
        let target = &mut self.entities[entity as usize];
        target.open = true;
        target.has_more = true;
        target.processed = 0;
        self.open_internal.push(OpenEntity {
            entity,
            start_tag_level: self.tag_level,
        });
        self.processor = Processor::InternalEntity;
        self.reenter = true;
        Ok(())
    }

    fn release_bindings(&mut self, bindings: &[u32]) {
        for &index in bindings.iter().rev() {
            let binding = &self.bindings[index as usize];
            let (prefix, previous) = (binding.prefix, binding.previous);
            self.prefixes[prefix as usize].binding = previous;
            self.free_bindings.push(index);
        }
    }

    /// `doCdataSection`: where the section ended.
    fn do_cdata_section(
        &mut self,
        enc: &Rc<Encoding>,
        d: &[u8],
        is_main: bool,
        mut s: usize,
        end: usize,
        account: Account,
    ) -> Result<usize, Stop> {
        if is_main {
            self.event_ptr = s;
        }
        loop {
            let mut next = s;
            let tok = enc.cdata_section_tok(d, s, end, &mut next);
            if !self.tolerated(tok, next - s, account) {
                return Err(XmlError::AmplificationLimitBreach.into());
            }
            match tok {
                TOK_CDATA_SECT_CLOSE => return Ok(next),
                TOK_DATA_NEWLINE => self.on_char(0xA),
                TOK_DATA_CHARS => self.on_data(enc, d, s, next, is_main)?,
                TOK_INVALID => {
                    if is_main {
                        self.event_ptr = next;
                    }
                    return Err(XmlError::InvalidToken.into());
                }
                TOK_PARTIAL_CHAR => return Err(XmlError::PartialChar.into()),
                _ => return Err(XmlError::UnclosedCdataSection.into()),
            }
            if is_main {
                self.event_ptr = next;
            }
            s = next;
        }
    }

    /// `addBinding`.
    fn add_binding(
        &mut self,
        prefix: u32,
        uri: &[u8],
        bindings: &mut Vec<u32>,
    ) -> Result<(), Stop> {
        let name = self.prefixes[prefix as usize].name.as_deref();
        // empty URI is only valid for the default namespace
        if uri.is_empty() && name.is_some() {
            return Err(XmlError::UndeclaringPrefix.into());
        }
        let mut must_be_xml = false;
        if let Some(name) = name {
            if name == b"xmlns" {
                return Err(XmlError::ReservedPrefixXmlns.into());
            }
            must_be_xml = name == b"xml";
        }
        if uri.contains(&NS_SEPARATOR) {
            return Err(XmlError::Syntax.into());
        }
        let is_xml = uri == XML_NAMESPACE;
        let is_xmlns = if must_be_xml {
            uri.len() == XMLNS_NAMESPACE.len()
        } else {
            uri == XMLNS_NAMESPACE
        };
        if must_be_xml != is_xml {
            return Err(if must_be_xml {
                XmlError::ReservedPrefixXml
            } else {
                XmlError::ReservedNamespaceUri
            }
            .into());
        }
        if is_xmlns {
            return Err(XmlError::ReservedNamespaceUri.into());
        }
        let previous = self.prefixes[prefix as usize].binding;
        let mut with_separator = Vec::with_capacity(uri.len() + 1);
        with_separator.extend_from_slice(uri);
        with_separator.push(NS_SEPARATOR);
        let binding = Binding {
            uri: with_separator,
            prefix,
            previous,
        };
        let index = if let Some(free) = self.free_bindings.pop() {
            self.bindings[free as usize] = binding;
            free
        } else {
            self.bindings.push(binding);
            self.bindings.len() as u32 - 1
        };
        // an empty default namespace undeclares it
        self.prefixes[prefix as usize].binding = if uri.is_empty() { None } else { Some(index) };
        bindings.push(index);
        Ok(())
    }

    /// `storeAtts`, with what `expat_start_handler` makes of the result.
    #[allow(clippy::too_many_arguments)]
    fn store_atts(
        &mut self,
        enc: &Rc<Encoding>,
        d: &[u8],
        is_main: bool,
        att_str: usize,
        name: &[u8],
        bindings: &mut Vec<u32>,
        account: Account,
    ) -> Result<Started, Stop> {
        let element_type = self.element_type(name);
        let mut atts = std::mem::take(&mut self.atts);
        enc.get_atts(d, att_str, &mut atts);
        let result = self.store_atts_with(
            enc,
            d,
            is_main,
            element_type,
            name,
            &atts,
            bindings,
            account,
        );
        self.atts = atts;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn store_atts_with(
        &mut self,
        enc: &Rc<Encoding>,
        d: &[u8],
        is_main: bool,
        element_type: u32,
        name: &[u8],
        atts: &[Attribute],
        bindings: &mut Vec<u32>,
        account: Account,
    ) -> Result<Started, Stop> {
        let mut app: Vec<(u32, Rc<[u8]>)> = Vec::with_capacity(atts.len());
        let mut touched: Vec<u32> = Vec::with_capacity(atts.len());
        for att in atts {
            let length = enc.name_length(d, att.name);
            let id = self.attribute_id(enc, d, att.name, att.name + length);
            if self.attribute_ids[id as usize].flag != 0 {
                if is_main {
                    self.event_ptr = att.name;
                }
                return Err(XmlError::DuplicateAttribute.into());
            }
            self.attribute_ids[id as usize].flag = 1;
            touched.push(id);
            let value: Vec<u8> = if att.normalized {
                let value = self.stored(enc, d, att.value, att.value_end);
                self.finish_value(value.len())?;
                value
            } else {
                let mut is_cdata = true;
                if self.attribute_ids[id as usize].maybe_tokenized {
                    let element = &self.types[element_type as usize];
                    if let Some(at) = element.default_for_name.get(&id) {
                        is_cdata = element.default_atts[*at].is_cdata;
                    }
                }
                self.store_attribute_value(
                    enc,
                    d,
                    is_main,
                    is_cdata,
                    att.value,
                    att.value_end,
                    account,
                )?
            };
            let attribute = &self.attribute_ids[id as usize];
            match attribute.prefix {
                Some(prefix) if attribute.xmlns => self.add_binding(prefix, &value, bindings)?,
                Some(_) => {
                    self.attribute_ids[id as usize].flag = 2;
                    app.push((id, Rc::from(value)));
                }
                None => app.push((id, Rc::from(value))),
            }
        }
        // do attribute defaulting, which costs Python a dict entry per element and no input
        for at in 0..self.types[element_type as usize].default_atts.len() {
            let default = &self.types[element_type as usize].default_atts[at];
            let (id, value) = (default.id, default.value.clone());
            let Some(value) = value else {
                continue;
            };
            let attribute = &self.attribute_ids[id as usize];
            if attribute.flag != 0 {
                continue;
            }
            self.expanded += value.len() + attribute.name.len() + size_of::<(String, String)>();
            if self.expanded > MAX_EXPANDED {
                return Err(Stop::Py(memory_error()));
            }
            match attribute.prefix {
                Some(prefix) if attribute.xmlns => self.add_binding(prefix, &value, bindings)?,
                Some(_) => {
                    self.attribute_ids[id as usize].flag = 2;
                    touched.push(id);
                    app.push((id, value));
                }
                None => {
                    self.attribute_ids[id as usize].flag = 1;
                    touched.push(id);
                    app.push((id, value));
                }
            }
        }
        // expand prefixed attribute names and check for duplicates
        let mut attrib = Vec::with_capacity(app.len());
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for (id, value) in &app {
            let attribute = &self.attribute_ids[*id as usize];
            let key = if attribute.flag == 2 {
                let Some(binding) = attribute
                    .prefix
                    .and_then(|p| self.prefixes[p as usize].binding)
                else {
                    return Err(XmlError::UnboundPrefix.into());
                };
                let colon = attribute.name.iter().position(|c| *c == b':').unwrap_or(0);
                let local = attribute.name.get(colon + 1..).unwrap_or(&[]);
                let uri = &self.bindings[binding as usize].uri;
                let mut expanded = Vec::with_capacity(uri.len() + local.len() + 1);
                expanded.push(b'{');
                expanded.extend_from_slice(uri);
                expanded.extend_from_slice(local);
                if !seen.insert(expanded.clone()) {
                    return Err(XmlError::DuplicateAttribute.into());
                }
                expanded
            } else {
                attribute.name.to_vec()
            };
            attrib.push((text_of(key), text_of(value.to_vec())));
        }
        for id in touched {
            self.attribute_ids[id as usize].flag = 0;
        }
        // expand the element type name
        let written = name
            .iter()
            .position(|c| *c == b':')
            .filter(|_| self.types[element_type as usize].prefix.is_some())
            .map(|colon| String::from_utf8_lossy(&name[..colon]).into_owned());
        let tag = if let Some(prefix) = self.types[element_type as usize].prefix {
            let Some(binding) = self.prefixes[prefix as usize].binding else {
                return Err(XmlError::UnboundPrefix.into());
            };
            let colon = name.iter().position(|c| *c == b':').unwrap_or(0);
            self.universal(binding, name.get(colon + 1..).unwrap_or(&[]))
        } else if let Some(binding) = self.prefixes[DEFAULT_PREFIX as usize].binding {
            self.universal(binding, name)
        } else {
            String::from_utf8_lossy(name).into_owned()
        };
        Ok(Started {
            tag,
            prefix: written,
            attrib,
        })
    }

    /// `makeuniversal` of `uri}local`.
    fn universal(&self, binding: u32, local: &[u8]) -> String {
        let uri = &self.bindings[binding as usize].uri;
        let mut out = Vec::with_capacity(uri.len() + local.len() + 1);
        out.push(b'{');
        out.extend_from_slice(uri);
        out.extend_from_slice(local);
        text_of(out)
    }

    /// `epilogProcessor`.
    fn epilog_processor(&mut self, mut s: usize) -> Result<usize, Stop> {
        let d = self.data;
        let end = d.len();
        let enc = Rc::clone(&self.enc);
        self.processor = Processor::Epilog;
        self.event_ptr = s;
        loop {
            let mut next = s;
            let tok = enc.prolog_tok(d, s, end, &mut next);
            if !self.tolerated(tok, next - s, Account::Direct) {
                return Err(XmlError::AmplificationLimitBreach.into());
            }
            match tok {
                t if t == -TOK_PROLOG_S => return Ok(next),
                TOK_NONE => return Ok(s),
                TOK_PROLOG_S | TOK_PI | TOK_COMMENT => {}
                TOK_INVALID => {
                    self.event_ptr = next;
                    return Err(XmlError::InvalidToken.into());
                }
                TOK_PARTIAL => return Err(XmlError::UnclosedToken.into()),
                TOK_PARTIAL_CHAR => return Err(XmlError::PartialChar.into()),
                _ => return Err(XmlError::JunkAfterDocElement.into()),
            }
            self.event_ptr = next;
            s = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(data: &[u8]) -> (String, String) {
        let error = fromstring(data).unwrap_err();
        (error.kind, error.message)
    }

    #[test]
    fn a_tree_is_elementtrees() {
        let root = fromstring(
            b"<!DOCTYPE r [<!ATTLIST r d CDATA \"v\"><!ENTITY e \"x&#38;#65;y\">]>\
              <r xmlns=\"urn:d\" xmlns:p=\"urn:p\" p:k=\"1\" n=\"2\" xml:lang=\"en\">\
              t&e;<!-- c -->u<![CDATA[<]]><p:c>i</p:c>tail<c/></r>",
        )
        .unwrap();
        assert_eq!(root.tag, "{urn:d}r");
        let attributes: Vec<(&str, &str)> = root
            .attrib
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            attributes,
            [
                ("{urn:p}k", "1"),
                ("n", "2"),
                ("{http://www.w3.org/XML/1998/namespace}lang", "en"),
                ("d", "v")
            ]
        );
        assert_eq!(root.text.as_deref(), Some("txAyu<"));
        assert_eq!(root.children[0].tag, "{urn:p}c");
        assert_eq!(root.children[0].text.as_deref(), Some("i"));
        assert_eq!(root.children[1].text, None);
        assert_eq!(root.iter_tag("{urn:d}c").len(), 1);
        assert_eq!(root.find_children("{urn:p}c").len(), 1);
        assert_eq!(root.get("n"), Some("2"));
    }

    #[test]
    fn encodings_are_expats_and_pythons() {
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend(
            "<a b=\"\u{e9}\">\u{20ac}\u{1F600}</a>"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let root = fromstring(&utf16).unwrap();
        assert_eq!(root.get("b"), Some("\u{e9}"));
        assert_eq!(root.text.as_deref(), Some("\u{20ac}\u{1F600}"));
        let root = fromstring(b"<?xml version=\"1.0\" encoding=\"windows-1252\"?><a>\x80\xe9</a>")
            .unwrap();
        assert_eq!(root.text.as_deref(), Some("\u{20ac}\u{e9}"));
    }

    #[test]
    fn errors_are_pythons() {
        let laughs = [
            &b"<!DOCTYPE a [<!ENTITY e \""[..],
            &[b'y'; 100000],
            b"\">]><a>",
            &b"&e;".repeat(100),
            b"</a>",
        ]
        .concat();
        let cases: &[(&[u8], &str, &str)] = &[
            (b"", "ParseError", "no element found: line 1, column 0"),
            (
                b"<a><b></a>",
                "ParseError",
                "mismatched tag: line 1, column 8",
            ),
            (
                b"<a/><b/>",
                "ParseError",
                "junk after document element: line 1, column 4",
            ),
            (
                b"<a>&b;</a>",
                "ParseError",
                "undefined entity: line 1, column 3",
            ),
            (
                b"<!DOCTYPE a SYSTEM \"x\"><a>\n &b;</a>",
                "ParseError",
                "undefined entity &b;: line 2, column 1",
            ),
            (
                b"<a x=\"1\" x=\"2\"/>",
                "ParseError",
                "duplicate attribute: line 1, column 9",
            ),
            (b"<p:a/>", "ParseError", "unbound prefix: line 1, column 0"),
            (b"<a", "ParseError", "unclosed token: line 1, column 0"),
            (
                b"<a><![CDATA[x",
                "ParseError",
                "unclosed CDATA section: line 1, column 13",
            ),
            (
                b"<?xml version=2?><a/>",
                "ParseError",
                "XML declaration not well-formed: line 1, column 14",
            ),
            (
                b"<a>&#0;</a>",
                "ParseError",
                "reference to invalid character number: line 1, column 3",
            ),
            (
                b"<a>\xff</a>",
                "ParseError",
                "not well-formed (invalid token): line 1, column 3",
            ),
            (
                b"<?xml version=\"1.0\" encoding=\"nope\"?><a/>",
                "LookupError",
                "unknown encoding: nope",
            ),
            (
                b"<?xml version=\"1.0\" encoding=\"shift_jis\"?><a/>",
                "ValueError",
                "multi-byte encodings are not supported",
            ),
            (
                b"<?xml version=\"1.0\" encoding=\"cp037\"?><a/>",
                "ParseError",
                "unknown encoding: line 1, column 30",
            ),
            (
                &laughs,
                "ParseError",
                "limit on input amplification factor (from DTD and entities) breached: line 1, column 100329",
            ),
        ];
        for (data, kind, message) in cases {
            assert_eq!(error(data), (kind.to_string(), message.to_string()));
        }
    }

    #[test]
    fn a_million_nested_elements_take_no_stack() {
        const DEPTH: usize = 1_000_000;
        let root = fromstring(&[b"<a>".repeat(DEPTH), b"</a>".repeat(DEPTH)].concat()).unwrap();
        assert_eq!(root.iter_tag("a").len(), DEPTH);
        let copy = root.clone();
        assert_eq!(copy.iter_tag("a").len(), DEPTH);
        assert!(format!("{copy:?}").ends_with("] }"));
        assert_eq!(
            error(&b"<a>".repeat(DEPTH)).1,
            "no element found: line 1, column 3000000"
        );
    }
}
