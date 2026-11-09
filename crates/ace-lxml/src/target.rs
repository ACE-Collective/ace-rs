//! `etree.parse(path, etree.XMLParser(target=obj))` with lxml 6.1.3's default `XMLParser`: libxml2
//! parses the XML and calls the target's `start(tag, attrib)`, `end(tag)` and `data(text)` as
//! lxml's `_TargetParserContext` does (`saxparser.pxi`, `parser.pxi`).
//!
//! What lxml sets up, and this does the same:
//!
//! - The options are `_XML_DEFAULT_PARSE_OPTIONS`: `NOENT | NOCDATA | NONET | COMPACT |
//!   BIG_LINES`. No `HUGE`, so libxml2's own limits hold, such as 256 levels of nesting, and no
//!   `RECOVER`, so the first fatal error stops the events and the parse raises.
//! - SAX2's default handlers, with `startElementNs`, `endElementNs`, `characters` and
//!   `cdataBlock` the target's, `startElement`, `endElement`, `reference`, `comment` and
//!   `processingInstruction` cleared, and entities always replaced. A target with no `comment`,
//!   `pi` or `doctype` method gets none of those events.
//! - `resolve_entities='internal'`: `getEntity` is SAX2's, but an external entity is refused, which
//!   makes the document not well-formed, so the parse raises when it ends. `getParameterEntity` is
//!   the same function, which looks in the general entities, so a parameter entity reference
//!   finds nothing and is passed over, as it is in lxml.
//! - A tag is `{uri}local`, or `local` with no namespace, and so is an attribute's name. Defaulted
//!   attributes are left out, as `attribute_defaults=False` has it.
//! - A file is read through zlib's `gzread`, as lxml's bundled libxml2 has zlib and reads a path
//!   with it: a gzip file is parsed as what it decompresses to, member after member, with trailing
//!   bytes that aren't another member ignored and a truncated or corrupt stream simply ending there.
//!   Anything else is read as it is. That libxml2 has no LZMA.
//!
//! lxml's `close()` runs either way and the exception follows it, so [`parse`] returns the error
//! after every event the target got.

use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fmt;
use std::io::Read;
use std::ptr;

use flate2::bufread::GzDecoder;

use crate::ffi::*;
use crate::init;

/// What the parser calls, as lxml's target methods.
pub trait Target {
    fn start(&mut self, tag: &str, attrib: &[(String, String)]);
    fn end(&mut self, tag: &str);
    fn data(&mut self, text: &str);
}

/// `XMLSyntaxError`: the document wasn't well-formed, or libxml2 refused it. The text is
/// libxml2's first error message, for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlSyntaxError(pub String);

impl fmt::Display for XmlSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XMLSyntaxError: {}", self.0)
    }
}

impl std::error::Error for XmlSyntaxError {}

const XML_PARSE_NOENT: c_int = 1 << 1;
const XML_PARSE_NONET: c_int = 1 << 11;
const XML_PARSE_NOCDATA: c_int = 1 << 14;
const XML_PARSE_COMPACT: c_int = 1 << 16;
const XML_PARSE_BIG_LINES: c_int = 1 << 22;
/// lxml's `_XML_DEFAULT_PARSE_OPTIONS`.
const XML_OPTIONS: c_int =
    XML_PARSE_NOENT | XML_PARSE_NOCDATA | XML_PARSE_NONET | XML_PARSE_COMPACT | XML_PARSE_BIG_LINES;

const XML_EXTERNAL_GENERAL_PARSED_ENTITY: c_int = 2;
const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: c_int = 3;
const XML_EXTERNAL_PARAMETER_ENTITY: c_int = 5;

/// The head of `entities.h`'s `xmlEntity`, up to its type.
#[repr(C)]
struct XmlEntityHead {
    _private: *mut c_void,
    type_: c_int,
    name: *const xmlChar,
    children: *mut c_void,
    last: *mut c_void,
    parent: *mut c_void,
    next: *mut c_void,
    prev: *mut c_void,
    doc: *mut c_void,
    orig: *mut xmlChar,
    content: *mut xmlChar,
    length: c_int,
    etype: c_int,
}

type StartNs = unsafe extern "C" fn(
    *mut c_void,
    *const xmlChar,
    *const xmlChar,
    *const xmlChar,
    c_int,
    *mut *const xmlChar,
    c_int,
    c_int,
    *mut *const xmlChar,
);
type EndNs = unsafe extern "C" fn(*mut c_void, *const xmlChar, *const xmlChar, *const xmlChar);
type GetEntity = unsafe extern "C" fn(*mut c_void, *const xmlChar) -> *mut XmlEntityHead;

unsafe extern "C" {
    fn xmlSAXVersion(hdlr: *mut xmlSAXHandler, version: c_int) -> c_int;
    fn xmlNewSAXParserCtxt(sax: *const xmlSAXHandler, user_data: *mut c_void)
    -> *mut xmlParserCtxt;
    fn xmlFreeParserCtxt(ctxt: *mut xmlParserCtxt);
    fn xmlCtxtReadIO(
        ctxt: *mut xmlParserCtxt,
        ioread: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int>,
        ioclose: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
        ioctx: *mut c_void,
        url: *const c_char,
        encoding: *const c_char,
        options: c_int,
    ) -> *mut xmlDoc;
    fn xmlSAX2GetEntity(ctx: *mut c_void, name: *const xmlChar) -> *mut XmlEntityHead;
    fn xmlGetLastError() -> *const XmlErrorHead;
    fn xmlCtxtGetLastError(ctxt: *mut c_void) -> *const XmlErrorHead;
    fn xmlResetLastError();
}

/// The head of `parser.h`'s `xmlParserCtxt`, up to `wellFormed`.
#[repr(C)]
struct XmlParserCtxtHead {
    sax: *mut c_void,
    user_data: *mut c_void,
    my_doc: *mut c_void,
    well_formed: c_int,
}

/// The head of `xmlerror.h`'s `xmlError`, up to its message.
#[repr(C)]
struct XmlErrorHead {
    domain: c_int,
    code: c_int,
    message: *const c_char,
}

/// The target of the parse running on this thread, and whether lxml would have marked the
/// document not well-formed.
struct Running<'t> {
    target: &'t mut dyn Target,
    refused_external: bool,
}

thread_local! {
    /// libxml2's SAX2 handlers want the parser context as their user data, so the target is found
    /// here rather than through it. A parse doesn't nest.
    static RUNNING: RefCell<Option<*mut Running<'static>>> = const { RefCell::new(None) };
}

fn with_running(f: impl FnOnce(&mut Running<'_>)) {
    RUNNING.with(|running| {
        if let Some(pointer) = *running.borrow() {
            // SAFETY: set by `parse` for the length of the libxml2 call that calls back here, on
            // this thread, and nothing else holds it meanwhile.
            f(unsafe { &mut *pointer });
        }
    });
}

/// libxml2's UTF-8, which it has checked. lxml decodes it with `.decode('utf8')`.
unsafe fn text<'a>(bytes: *const xmlChar, len: usize) -> std::borrow::Cow<'a, str> {
    if bytes.is_null() {
        return "".into();
    }
    let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
    String::from_utf8_lossy(slice)
}

unsafe fn c_text<'a>(bytes: *const xmlChar) -> std::borrow::Cow<'a, str> {
    if bytes.is_null() {
        return "".into();
    }
    unsafe { CStr::from_ptr(bytes.cast()) }.to_string_lossy()
}

/// `_namespacedNameFromNsName`.
unsafe fn clark(uri: *const xmlChar, local: *const xmlChar) -> String {
    let local = unsafe { c_text(local) };
    if uri.is_null() {
        local.into_owned()
    } else {
        format!("{{{}}}{local}", unsafe { c_text(uri) })
    }
}

/// `_handleSaxTargetStart`.
#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn on_start(
    _: *mut c_void,
    localname: *const xmlChar,
    _prefix: *const xmlChar,
    uri: *const xmlChar,
    _nb_namespaces: c_int,
    _namespaces: *mut *const xmlChar,
    nb_attributes: c_int,
    nb_defaulted: c_int,
    attributes: *mut *const xmlChar,
) {
    let tag = unsafe { clark(uri, localname) };
    // defaulted attributes only when asked for (`attribute_defaults`)
    let count = usize::try_from(nb_attributes - nb_defaulted.max(0)).unwrap_or(0);
    let mut attrib: Vec<(String, String)> = Vec::with_capacity(count);
    for i in 0..count {
        let a = unsafe { attributes.add(i * 5) };
        let (local, uri, value, end) = unsafe { (*a, *a.add(2), *a.add(3), *a.add(4)) };
        let name = unsafe { clark(uri, local) };
        let value = if value.is_null() {
            String::new()
        } else {
            let len = usize::try_from(unsafe { end.offset_from(value) }).unwrap_or(0);
            unsafe { text(value, len) }.into_owned()
        };
        // a dict: a name given again keeps its first place and its last value
        match attrib.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = value,
            None => attrib.push((name, value)),
        }
    }
    with_running(|running| running.target.start(&tag, &attrib));
}

/// `_handleSaxEnd`.
unsafe extern "C" fn on_end(
    _: *mut c_void,
    localname: *const xmlChar,
    _prefix: *const xmlChar,
    uri: *const xmlChar,
) {
    let tag = unsafe { clark(uri, localname) };
    with_running(|running| running.target.end(&tag));
}

/// `_handleSaxData`, for characters and CDATA.
unsafe extern "C" fn on_data(_: *mut c_void, chars: *const xmlChar, len: c_int) {
    let data = unsafe { text(chars, usize::try_from(len).unwrap_or(0)) };
    with_running(|running| running.target.data(&data));
}

/// `_getInternalEntityOnly`: SAX2's lookup, but an external entity is refused and the document
/// marked not well-formed.
unsafe extern "C" fn on_get_entity(ctx: *mut c_void, name: *const xmlChar) -> *mut XmlEntityHead {
    let entity = unsafe { xmlSAX2GetEntity(ctx, name) };
    if entity.is_null() {
        return entity;
    }
    let etype = unsafe { (*entity).etype };
    if !matches!(
        etype,
        XML_EXTERNAL_GENERAL_PARSED_ENTITY
            | XML_EXTERNAL_GENERAL_UNPARSED_ENTITY
            | XML_EXTERNAL_PARAMETER_ENTITY
    ) {
        return entity;
    }
    // not well-formed, which also keeps libxml2 from looking the entity up itself after this
    // returns nothing (`xmlParseEntityRefInternal`), as lxml has it
    unsafe { (*(ctx as *mut XmlParserCtxtHead)).well_formed = 0 };
    with_running(|running| running.refused_external = true);
    ptr::null_mut()
}

unsafe extern "C" fn ignore_error(_: *mut c_void, _: *const xmlError) {}

/// What `gzread` gives for a file: its gzip members' contents, or the bytes themselves when it
/// doesn't start like gzip.
enum Source<'b> {
    Plain(&'b [u8]),
    Gzip {
        decoder: Option<Box<GzDecoder<&'b [u8]>>>,
    },
}

impl<'b> Source<'b> {
    fn new(bytes: &'b [u8]) -> Self {
        if bytes.starts_with(&[0x1f, 0x8b]) {
            Source::Gzip {
                decoder: Some(Box::new(GzDecoder::new(bytes))),
            }
        } else {
            Source::Plain(bytes)
        }
    }
}

impl Read for Source<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Source::Plain(bytes) => bytes.read(buf),
            Source::Gzip { decoder } => loop {
                let Some(current) = decoder.as_mut() else {
                    return Ok(0);
                };
                match current.read(buf) {
                    Ok(0) if !buf.is_empty() => {
                        // the member ended: another follows only if the next bytes start one
                        let rest = decoder.take().map(|d| d.into_inner()).unwrap_or(&[]);
                        if rest.starts_with(&[0x1f, 0x8b]) {
                            *decoder = Some(Box::new(GzDecoder::new(rest)));
                        } else {
                            return Ok(0);
                        }
                    }
                    Ok(n) => return Ok(n),
                    // a truncated or corrupt stream ends where it breaks
                    Err(_) => {
                        *decoder = None;
                        return Ok(0);
                    }
                }
            },
        }
    }
}

unsafe extern "C" fn read_source(context: *mut c_void, buffer: *mut c_char, len: c_int) -> c_int {
    let source = unsafe { &mut *(context as *mut Source<'_>) };
    let wanted = usize::try_from(len).unwrap_or(0);
    let buf = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), wanted) };
    match source.read(buf) {
        Ok(n) => c_int::try_from(n).unwrap_or(0),
        Err(_) => -1,
    }
}

/// Clears the thread's target when the parse ends, however it ends.
struct Clear;

impl Drop for Clear {
    fn drop(&mut self) {
        RUNNING.with(|running| *running.borrow_mut() = None);
    }
}

/// Parses `bytes` as lxml parses a file with a target parser, calling `target` for each event.
/// Returns the `XMLSyntaxError` lxml raises after the target's `close()`, if any.
pub fn parse(bytes: &[u8], target: &mut dyn Target) -> Result<(), XmlSyntaxError> {
    init();
    let mut source = Source::new(bytes);
    let mut running = Running {
        target,
        refused_external: false,
    };
    // SAFETY: the pointer is cleared by `Clear` before `running` goes out of scope; the lifetime is
    // erased only for the thread-local's type.
    let pointer: *mut Running<'static> = std::ptr::from_mut(&mut running).cast();
    RUNNING.with(|r| *r.borrow_mut() = Some(pointer));
    let _clear = Clear;
    let (well_formed, message) = unsafe {
        let mut sax: xmlSAXHandler = std::mem::zeroed();
        xmlSAXVersion(&mut sax, 2);
        sax.startElementNs = on_start as StartNs as *mut c_void;
        sax.endElementNs = on_end as EndNs as *mut c_void;
        sax.startElement = None;
        sax.endElement = None;
        sax.characters = Some(on_data);
        sax.cdataBlock = Some(on_data);
        sax.reference = ptr::null_mut();
        sax.processingInstruction = None;
        sax.comment = None;
        sax.getEntity = on_get_entity as GetEntity as *mut c_void;
        // lxml gives parameter entities the same lookup, in the general entities, so a reference to
        // one finds nothing unless a general entity has its name
        sax.getParameterEntity = on_get_entity as GetEntity as *mut c_void;
        sax.serror = Some(ignore_error);
        let ctxt = xmlNewSAXParserCtxt(&sax, ptr::null_mut());
        if ctxt.is_null() {
            return Err(XmlSyntaxError("out of memory".to_owned()));
        }
        xmlCtxtSetErrorHandler(ctxt, Some(ignore_error), ptr::null_mut());
        xmlResetLastError();
        let doc = xmlCtxtReadIO(
            ctxt,
            Some(read_source),
            None,
            &mut source as *mut Source<'_> as *mut c_void,
            ptr::null(),
            ptr::null(),
            XML_OPTIONS,
        );
        let well_formed = !doc.is_null();
        if !doc.is_null() {
            xmlFreeDoc(doc);
        }
        let mut error = xmlCtxtGetLastError(ctxt.cast());
        if error.is_null() {
            error = xmlGetLastError();
        }
        let message = if error.is_null() || (*error).message.is_null() {
            String::new()
        } else {
            CStr::from_ptr((*error).message)
                .to_string_lossy()
                .trim_end()
                .to_owned()
        };
        xmlFreeParserCtxt(ctxt);
        (well_formed, message)
    };
    drop(_clear);
    if !well_formed {
        return Err(XmlSyntaxError(message));
    }
    if running.refused_external {
        return Err(XmlSyntaxError(
            "External entity resolution is disabled for security reasons".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Events(Vec<String>);

    impl Target for Events {
        fn start(&mut self, tag: &str, attrib: &[(String, String)]) {
            self.0.push(format!("start {tag} {attrib:?}"));
        }
        fn end(&mut self, tag: &str) {
            self.0.push(format!("end {tag}"));
        }
        fn data(&mut self, text: &str) {
            match self.0.last_mut() {
                Some(last) if last.starts_with("data ") => last.push_str(text),
                _ => self.0.push(format!("data {text}")),
            }
        }
    }

    #[test]
    fn events_are_lxml_s() {
        let mut events = Events::default();
        parse(
            b"<?xml version='1.0'?><!DOCTYPE r [<!ENTITY e 'v&amp;'>]><r xmlns='u' xmlns:p='q' p:a='1' b='&e;'><![CDATA[x<]]>&e;<!--c--><?pi?></r>",
            &mut events,
        )
        .unwrap();
        assert_eq!(
            events.0,
            [
                r#"start {u}r [("{q}a", "1"), ("b", "v&")]"#,
                "data x<v&",
                "end {u}r"
            ]
        );
    }

    #[test]
    fn an_error_stops_the_events_and_raises() {
        let mut events = Events::default();
        let error = parse(b"<a><b>t</c></a>", &mut events).unwrap_err();
        assert!(!error.0.is_empty());
        assert_eq!(events.0, ["start a []", "start b []", "data t"]);
        assert!(parse(b"", &mut Events::default()).is_err());
    }

    #[test]
    fn external_entities_are_refused_after_the_parse() {
        let mut events = Events::default();
        let error = parse(
            b"<!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;<s/></r>",
            &mut events,
        );
        assert!(error.is_err());
        assert_eq!(events.0, ["start r []"]);
        // with an external subset the entity may be declared there, so the parse goes on, and
        // lxml doesn't load the subset
        let mut events = Events::default();
        parse(b"<!DOCTYPE r SYSTEM 'x.dtd'><r>&x;<s/></r>", &mut events).unwrap();
        assert_eq!(events.0, ["start r []", "start s []", "end s", "end r"]);
    }

    #[test]
    fn gzip_is_read_as_gzread_reads_it() {
        use std::io::Write;
        let gz = |data: &[u8]| {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        };
        let mut two = gz(b"<r>z");
        two.extend(gz(b"</r>"));
        two.extend(b"junk");
        let mut events = Events::default();
        parse(&two, &mut events).unwrap();
        assert_eq!(events.0, ["start r []", "data z", "end r"]);
        assert!(parse(b"\x1f\x8b<r/>", &mut Events::default()).is_err());
    }
}
