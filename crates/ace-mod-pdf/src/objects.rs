//! What ace3's `PDFAnalyzer` reads through pikepdf, on libqpdf directly. It's written against
//! pikepdf's behaviour rather than the PDF specification, because ace3's `try` blocks turn that
//! behaviour into results: an exception part way through a list loses what was gathered.
//!
//! `Py` is what an attribute comes back as in Python: pikepdf hands nulls, booleans, integers and
//! reals over as Python's own, and those have no `.get`. A failure is a `Raised` with Python's type
//! and message, so `tools/library-diff/run pikepdf` can compare them.

use std::collections::BTreeSet;

use crate::pdfparser::bytes_repr;
use crate::qpdf::{Document, Handle, Kind, Raised};

/// A value as Python sees it.
#[derive(Debug, Clone)]
pub enum Py {
    None,
    Bool(bool),
    Int(i64),
    Decimal(Vec<u8>),
    /// A string the code supplied, the `'unknown'` of `field.get('/T', 'unknown')`.
    Str(&'static str),
    /// The `[]` of `.get('/Fields', [])`.
    EmptyList,
    /// One of pikepdf's objects.
    Object(Handle),
}

impl Py {
    /// `type(self).__name__`.
    fn type_name(&self) -> &'static str {
        match self {
            Py::None => "NoneType",
            Py::Bool(_) => "bool",
            Py::Int(_) => "int",
            Py::Decimal(_) => "decimal.Decimal",
            Py::Str(_) => "str",
            Py::EmptyList => "list",
            Py::Object(_) => "pikepdf._core.Object",
        }
    }
}

/// The text Python's `bytes.decode()` makes, with its error.
fn utf8(bytes: Vec<u8>) -> Result<String, Raised> {
    String::from_utf8(bytes).map_err(|e| {
        let error = e.utf8_error();
        let at = error.valid_up_to();
        let byte = e.as_bytes()[at];
        let message = match error.error_len() {
            None => "unexpected end of data",
            Some(_) if (0xC2..=0xF4).contains(&byte) => "invalid continuation byte",
            Some(_) => "invalid start byte",
        };
        let end = e.as_bytes().len();
        if error.error_len().is_none() && end - at > 1 {
            Raised::new(
                "UnicodeDecodeError",
                format!(
                    "'utf-8' codec can't decode bytes in position {at}-{}: {message}",
                    end - 1
                ),
            )
        } else {
            Raised::new(
                "UnicodeDecodeError",
                format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {at}: {message}"),
            )
        }
    })
}

/// The file's objects as pikepdf gives them.
pub struct Objects<'a> {
    pub document: &'a Document,
}

impl Objects<'_> {
    /// Casts an object to Python.
    fn py(&self, object: Handle) -> Result<Py, Raised> {
        let document = self.document;
        let value = match document.kind(object)? {
            Kind::Null => Py::None,
            Kind::Bool => Py::Bool(document.bool_value(object)?),
            Kind::Integer => Py::Int(document.int_value(object)?),
            Kind::Real => Py::Decimal(document.real_value(object)?),
            _ => return Ok(Py::Object(object)),
        };
        // Python holds the value itself, so the handle is given back: libqpdf keeps one until then
        document.release(object);
        Ok(value)
    }

    /// `value.get(key)`: an object that isn't a dictionary or stream gives None, and Python's own
    /// values raise.
    pub fn get(&self, value: &Py, key: &str) -> Result<Py, Raised> {
        match value {
            Py::Object(object) => match self.document.key(*object, key)? {
                Some(found) => self.py(found),
                None => Ok(Py::None),
            },
            other => Err(Raised::new(
                "AttributeError",
                format!("'{}' object has no attribute 'get'", other.type_name()),
            )),
        }
    }

    /// `bool(value)`.
    pub fn truthy(&self, value: &Py) -> Result<bool, Raised> {
        let document = self.document;
        Ok(match value {
            Py::None | Py::EmptyList => false,
            Py::Bool(value) => *value,
            Py::Int(value) => *value != 0,
            Py::Decimal(text) => String::from_utf8_lossy(text)
                .parse::<f64>()
                .is_ok_and(|v| v != 0.0),
            Py::Str(text) => !text.is_empty(),
            Py::Object(object) => match document.kind(*object)? {
                Kind::Dictionary => !document.keys(*object)?.is_empty(),
                Kind::Array => document.array_len(*object)? > 0,
                Kind::Stream => match document.key(*object, "/Length")? {
                    Some(length) if document.kind(length)? == Kind::Integer => {
                        document.int_value(length)? > 0
                    }
                    _ => false,
                },
                Kind::String => !document.string_bytes(*object)?.is_empty(),
                Kind::Name => document.name(*object)?.len() > 1,
                _ => false,
            },
        })
    }

    /// `iter(value)`, as its items. A dictionary or stream iterates over its keys, as `str`, and
    /// what those are matters only in that they have no `.get`.
    pub fn items(&self, value: &Py) -> Result<Vec<Py>, Raised> {
        let document = self.document;
        match value {
            Py::EmptyList => Ok(Vec::new()),
            Py::Object(object) => match document.kind(*object)? {
                Kind::Array => {
                    let mut items = Vec::new();
                    for i in 0..document.array_len(*object)? {
                        items.push(self.py(document.array_item(*object, i)?)?);
                    }
                    Ok(items)
                }
                Kind::Dictionary | Kind::Stream => Ok(document
                    .keys(*object)?
                    .iter()
                    .map(|_| Py::Str(""))
                    .collect()),
                _ => Err(Raised::new(
                    "TypeError",
                    "__iter__ not available on this type",
                )),
            },
            other => Err(Raised::new(
                "TypeError",
                format!("'{}' object is not iterable", other.type_name()),
            )),
        }
    }

    /// `str(value)`.
    pub fn text(&self, value: &Py) -> Result<String, Raised> {
        let document = self.document;
        match value {
            Py::None => Ok("None".to_owned()),
            Py::Bool(value) => Ok(if *value { "True" } else { "False" }.to_owned()),
            Py::Int(value) => Ok(value.to_string()),
            Py::Decimal(text) => Ok(decimal_text(text)),
            Py::Str(text) => Ok((*text).to_owned()),
            Py::EmptyList => Ok("[]".to_owned()),
            Py::Object(object) => match document.kind(*object)? {
                Kind::Name => utf8(document.name(*object)?),
                Kind::String => utf8(document.string_utf8(*object)?),
                _ => self.repr(*object),
            },
        }
    }

    /// `objecthandle_repr` in pikepdf's `object_repr.cpp`, which `str()` falls back on.
    fn repr(&self, object: Handle) -> Result<String, Raised> {
        let document = self.document;
        let kind = document.kind(object)?;
        let mut visited = BTreeSet::new();
        let mut pure = true;
        let mut count = 0;
        let mut inner = Vec::new();
        self.repr_inner(
            &mut inner,
            object,
            0,
            0,
            &mut count,
            &mut visited,
            &mut pure,
        )?;
        let output = match kind {
            Kind::Array => {
                let mut output = b"pikepdf.Array(".to_vec();
                output.extend_from_slice(&inner);
                output.push(b')');
                output
            }
            Kind::Dictionary => {
                let mut output = self.dictionary_name(object)?;
                output.push(b'(');
                output.extend_from_slice(&inner);
                output.push(b')');
                output
            }
            _ => {
                pure = false;
                inner
            }
        };
        let output = if pure {
            output
        } else {
            let mut wrapped = vec![b'<'];
            wrapped.extend_from_slice(&output);
            wrapped.push(b'>');
            wrapped
        };
        utf8(output)
    }

    fn dictionary_name(&self, object: Handle) -> Result<Vec<u8>, Raised> {
        let document = self.document;
        let mut name = b"pikepdf.Dictionary".to_vec();
        if let Some(kind) = document.key(object, "/Type")? {
            name.extend_from_slice(b"(Type=\"");
            name.extend_from_slice(&document.name(kind)?);
            name.extend_from_slice(b"\")");
        }
        Ok(name)
    }

    #[allow(clippy::too_many_arguments)]
    fn repr_inner(
        &self,
        out: &mut Vec<u8>,
        object: Handle,
        recursion: u32,
        indent: usize,
        count: &mut u32,
        visited: &mut BTreeSet<(i32, i32)>,
        pure: &mut bool,
    ) -> Result<(), Raised> {
        let document = self.document;
        let kind = document.kind(object)?;
        let id = document.id(object);
        let scalar = !matches!(
            kind,
            Kind::Array | Kind::Dictionary | Kind::Stream | Kind::Other
        );
        if !scalar {
            if visited.contains(&id) {
                *pure = false;
                out.extend_from_slice(format!("<.get_object({} {})>", id.0, id.1).as_bytes());
                return Ok(());
            }
            if id != (0, 0) {
                visited.insert(id);
            }
        }
        if recursion >= 1 && id != (0, 0) && document.is_dictionary_of_type(object, c"/Page")? {
            out.extend_from_slice(format!("<Pdf.pages.from_objgen({} {})>", id.0, id.1).as_bytes());
            return Ok(());
        }
        *count += 1;
        if *count > 40 && recursion > 1 {
            *pure = false;
            out.extend_from_slice(b"<...>");
            return Ok(());
        }
        match kind {
            Kind::Null => out.extend_from_slice(b"None"),
            Kind::Name => quoted(out, &document.name(object)?),
            Kind::String => quoted(out, &document.string_utf8(object)?),
            Kind::Bool => {
                out.extend_from_slice(if document.bool_value(object)? {
                    b"True"
                } else {
                    b"False"
                });
            }
            Kind::Integer => {
                out.extend_from_slice(document.int_value(object)?.to_string().as_bytes());
            }
            Kind::Real => {
                out.extend_from_slice(b"Decimal('");
                out.extend_from_slice(&document.real_value(object)?);
                out.extend_from_slice(b"')");
            }
            Kind::Array => {
                out.extend_from_slice(b"[ ");
                for i in 0..document.array_len(object)? {
                    if i > 0 {
                        out.extend_from_slice(b", ");
                    }
                    let item = document.array_item(object, i)?;
                    self.repr_inner(out, item, recursion + 1, indent, count, visited, pure)?;
                }
                out.extend_from_slice(b" ]");
            }
            Kind::Dictionary => {
                out.extend_from_slice(b"{\n");
                let mut first = true;
                for key in document.keys(object)? {
                    if !first {
                        out.extend_from_slice(b",\n");
                    }
                    first = false;
                    out.resize(out.len() + (indent + 1) * 2, b' ');
                    quoted(out, &key);
                    let name = String::from_utf8_lossy(&key).into_owned();
                    let value = document.key(object, &name)?;
                    out.extend_from_slice(b": ");
                    match value {
                        Some(value)
                            if key == b"/Parent"
                                && document.is_dictionary_of_type(value, c"/Pages")? =>
                        {
                            out.extend_from_slice(b"<reference to /Pages>");
                        }
                        Some(value) => {
                            self.repr_inner(
                                out,
                                value,
                                recursion + 1,
                                indent + 1,
                                count,
                                visited,
                                pure,
                            )?;
                        }
                        None => out.extend_from_slice(b"None"),
                    }
                }
                out.push(b'\n');
                out.resize(out.len() + indent * 2, b' ');
                out.push(b'}');
            }
            Kind::Stream => {
                *pure = false;
                out.extend_from_slice(b"pikepdf.Stream(owner=<...>, data=");
                self.stream_preview(out, object, recursion)?;
                out.extend_from_slice(b", ");
                // a stream's dictionary, which `key` looks through, printed as a dictionary
                self.repr_dict_of_stream(out, object, recursion + 1, indent, count, visited, pure)?;
                out.push(b')');
            }
            Kind::Other => {}
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn repr_dict_of_stream(
        &self,
        out: &mut Vec<u8>,
        stream: Handle,
        recursion: u32,
        indent: usize,
        count: &mut u32,
        visited: &mut BTreeSet<(i32, i32)>,
        pure: &mut bool,
    ) -> Result<(), Raised> {
        let document = self.document;
        *count += 1;
        if *count > 40 && recursion > 1 {
            *pure = false;
            out.extend_from_slice(b"<...>");
            return Ok(());
        }
        out.extend_from_slice(b"{\n");
        let mut first = true;
        for key in document.keys(stream)? {
            if !first {
                out.extend_from_slice(b",\n");
            }
            first = false;
            out.resize(out.len() + (indent + 1) * 2, b' ');
            quoted(out, &key);
            out.extend_from_slice(b": ");
            let name = String::from_utf8_lossy(&key).into_owned();
            match document.key(stream, &name)? {
                Some(value) => {
                    self.repr_inner(out, value, recursion + 1, indent + 1, count, visited, pure)?
                }
                None => out.extend_from_slice(b"None"),
            }
        }
        out.push(b'\n');
        out.resize(out.len() + indent * 2, b' ');
        out.push(b'}');
        Ok(())
    }

    /// `preview_stream_data`.
    fn stream_preview(
        &self,
        out: &mut Vec<u8>,
        stream: Handle,
        recursion: u32,
    ) -> Result<(), Raised> {
        let document = self.document;
        let length = match document.key(stream, "/Length")? {
            Some(length) if document.kind(length)? == Kind::Integer => {
                document.int_value(length)?
            }
            _ => -1,
        };
        if recursion > 1 || !(0..=10000).contains(&length) {
            out.extend_from_slice(b"<...>");
            return Ok(());
        }
        match document.stream_data(stream) {
            Ok(data) => {
                out.extend_from_slice(&bytes_repr(&data[..data.len().min(20)]));
                if data.len() > 20 {
                    out.extend_from_slice(b"...");
                }
            }
            Err(_) => out.extend_from_slice(b"<...>"),
        }
        Ok(())
    }

    /// Gives back the handle of a value that is one of pikepdf's objects, which nothing may use
    /// after.
    pub fn release(&self, value: &Py) {
        if let Py::Object(object) = value {
            self.document.release(*object);
        }
    }

    /// ace3's `iter_uri_annotations`: each annotation whose action opens a URI, with its page, numbered
    /// from 1: `action.get('/URI')` of each annotation with an action, kept when it's true in Python.
    /// `each` returns false to stop. What it is handed is good only until it returns: an array of
    /// annotations is read one at a time and each one's handles are given back, since a PDF can repeat
    /// one annotation without limit.
    pub fn each_uri_annotation(
        &self,
        mut each: impl FnMut(&UriAnnotation) -> Result<bool, Raised>,
    ) -> Result<(), Raised> {
        let document = self.document;
        for index in 0..document.page_count()? {
            let page = Py::Object(document.page(index)?);
            let annots = self.get(&page, "/Annots")?;
            if !self.truthy(&annots)? {
                self.release(&annots);
                self.release(&page);
                continue;
            }
            let array = match &annots {
                Py::Object(object) if document.kind(*object)? == Kind::Array => Some(*object),
                _ => None,
            };
            // what isn't an array iterates as Python has it: a dictionary's keys, which have no
            // `.get`, or an error
            let rest = match array {
                Some(_) => Vec::new(),
                None => self.items(&annots)?,
            };
            let count = match array {
                Some(object) => document.array_len(object)?,
                None => rest.len() as i32,
            };
            for i in 0..count {
                let annot = match array {
                    Some(object) => self.py(document.array_item(object, i)?)?,
                    None => rest[i as usize].clone(),
                };
                let action = self.get(&annot, "/A")?;
                let uri = if self.truthy(&action)? {
                    self.get(&action, "/URI")?
                } else {
                    Py::None
                };
                let go_on = if self.truthy(&uri)? {
                    each(&UriAnnotation {
                        page_number: index + 1,
                        page: page.clone(),
                        annot: annot.clone(),
                        uri: uri.clone(),
                    })?
                } else {
                    true
                };
                self.release(&uri);
                self.release(&action);
                self.release(&annot);
                if !go_on {
                    return Ok(());
                }
            }
            self.release(&annots);
            self.release(&page);
        }
        Ok(())
    }

    /// What the annotations hold: what `read` makes of the URI of each of `each_uri_annotation`'s,
    /// such as its text.
    pub fn annotation_uris<T>(
        &self,
        mut read: impl FnMut(&Py) -> Result<T, Raised>,
    ) -> Result<Vec<T>, Raised> {
        let mut uris = Vec::new();
        self.each_uri_annotation(|found| {
            uris.push(read(&found.uri)?);
            Ok(true)
        })?;
        Ok(uris)
    }

    /// `float(value)` of an item of a PDF array as pikepdf hands it over.
    pub fn float(&self, value: &Py) -> Result<f64, Raised> {
        match value {
            Py::Bool(value) => Ok(if *value { 1.0 } else { 0.0 }),
            Py::Int(value) => Ok(*value as f64),
            Py::Decimal(text) => decimal_float(text),
            Py::Str(text) => Err(Raised::new(
                "ValueError",
                format!("could not convert string to float: '{text}'"),
            )),
            Py::Object(_) => Err(Raised::new("TypeError", "Object is not numeric")),
            other => Err(Raised::new(
                "TypeError",
                format!(
                    "float() argument must be a string or a real number, not '{}'",
                    other.type_name()
                ),
            )),
        }
    }

    /// `page.mediabox` as floats: the page's `/MediaBox`, its own or the one libqpdf pushed down to
    /// it when the file was opened, when that is an array of four numbers, and US Letter otherwise,
    /// which is what pikepdf gives a page with none it can read.
    pub fn mediabox(&self, page: &Py) -> Result<[f64; 4], Raised> {
        const LETTER: [f64; 4] = [0.0, 0.0, 612.0, 792.0];
        let document = self.document;
        let Py::Object(page) = page else {
            return Ok(LETTER);
        };
        let Some(found) = document.key(*page, "/MediaBox")? else {
            return Ok(LETTER);
        };
        if document.kind(found)? != Kind::Array || document.array_len(found)? != 4 {
            return Ok(LETTER);
        }
        let mut bounds = [0.0; 4];
        for (i, bound) in bounds.iter_mut().enumerate() {
            let item = document.array_item(found, i as i32)?;
            *bound = match document.kind(item)? {
                Kind::Integer => document.int_value(item)? as f64,
                Kind::Real => decimal_float(&document.real_value(item)?)?,
                _ => return Ok(LETTER),
            };
        }
        Ok(bounds)
    }

    /// `pdf.Root.get('/AcroForm')`'s `/Fields`, or nothing to look through.
    pub fn form_fields(&self) -> Result<Vec<Py>, Raised> {
        let root = Py::Object(self.document.root()?);
        let acroform = self.get(&root, "/AcroForm")?;
        if !self.truthy(&acroform)? {
            return Ok(Vec::new());
        }
        match self.get(&acroform, "/Fields")? {
            Py::None => Ok(Vec::new()),
            fields => self.items(&fields),
        }
    }

    /// `field.get('/T', 'unknown')`.
    pub fn field_name(&self, field: &Py) -> Result<Py, Raised> {
        Ok(match self.get(field, "/T")? {
            Py::None => Py::Str("unknown"),
            name => name,
        })
    }

    /// The items of `/Names /JavaScript /Names`, as pairs: ace3 takes this one level of the name
    /// tree, and pairs from `range(0, len - 1, 2)`.
    pub fn javascript(&self) -> Result<Vec<(Py, Py)>, Raised> {
        let document = self.document;
        let root = Py::Object(document.root()?);
        let names = self.get(&root, "/Names")?;
        if !self.truthy(&names)? {
            return Ok(Vec::new());
        }
        let tree = self.get(&names, "/JavaScript")?;
        if !self.truthy(&tree)? {
            return Ok(Vec::new());
        }
        let array = self.get(&tree, "/Names")?;
        let items = match &array {
            Py::None => Vec::new(),
            Py::Object(object) if document.kind(*object)? == Kind::Array => self.items(&array)?,
            // pikepdf's len(): a dictionary has one, and indexing it raises when it's long enough
            // for the loop to run. Everything else raises at the len().
            Py::Object(object) => match document.kind(*object)? {
                Kind::Dictionary if document.keys(*object)?.len() < 2 => Vec::new(),
                Kind::Dictionary => {
                    return Err(Raised::new(
                        "TypeError",
                        "pikepdf.Object is not an Array: cannot index object of type dictionary",
                    ));
                }
                Kind::Stream => {
                    return Err(Raised::new(
                        "TypeError",
                        "length not defined for object - use len(obj.keys()) for number of \
                         dictionary keys, or len(bytes(obj)) for length of stream data",
                    ));
                }
                _ => return Err(Raised::new("TypeError", "length not defined for object")),
            },
            other => {
                return Err(Raised::new(
                    "TypeError",
                    format!("object of type '{}' has no len()", other.type_name()),
                ));
            }
        };
        let mut pairs = Vec::new();
        let mut i = 0;
        while i + 1 < items.len() {
            pairs.push((items[i].clone(), items[i + 1].clone()));
            i += 2;
        }
        Ok(pairs)
    }

    /// What's in a PDF object, for the side `tools/library-diff/run` compares, in the shape of
    /// `value_of` in `tools/library-diff/adapters/pikepdf.py`.
    pub fn value_of(&self, value: &Py) -> Result<serde_json::Value, Raised> {
        let document = self.document;
        use serde_json::json;
        if let Py::Object(object) = value {
            match document.kind(*object)? {
                Kind::Stream => {
                    return Ok(json!({"stream": bytes_json(document.stream_data(*object)?)}));
                }
                Kind::Name => return Ok(json!({"name": self.text(value)?})),
                Kind::String => {
                    return Ok(json!({
                        "text": self.text(value)?,
                        "bytes": bytes_json(document.string_bytes(*object)?),
                    }));
                }
                _ => {}
            }
        }
        Ok(json!({"other": self.text(value)?}))
    }

    /// `pdf.encryption` and the rest of what `save_decrypted_copy` puts in the analysis's details.
    pub fn encryption(&self, path: &std::path::Path) -> Result<Encryption, Raised> {
        let document = self.document;
        let job = crate::qpdf::encryption_json(path)?;
        let parameters = &job["parameters"];
        let capabilities = &job["capabilities"];
        let number = |key: &str| parameters[key].as_i64().unwrap_or_default();
        let flag = |key: &str| capabilities[key].as_bool().unwrap_or_default();
        let v = number("V");
        let trailer = Py::Object(document.trailer()?);
        let dictionary = self.get(&trailer, "/Encrypt")?;
        let filter = match self.get(&dictionary, "/Filter")? {
            Py::None => String::new(),
            filter => self.text(&filter)?,
        };
        let method = if v < 4 {
            "rc4".to_owned()
        } else {
            match parameters["streammethod"].as_str().unwrap_or_default() {
                "AESv2" => "aes".to_owned(),
                "AESv3" => "aesv3".to_owned(),
                // the job shows a method of none as RC4, so look at the crypt filter
                "RC4" => self.stream_crypt_filter(&dictionary)?,
                other => other.to_owned(),
            }
        };
        Ok(Encryption {
            filter,
            v,
            r: number("R"),
            p: number("P"),
            bits: number("bits"),
            method,
            owner_password_empty: job["ownerpasswordmatched"].as_bool().unwrap_or_default(),
            permissions: Permissions {
                accessibility: flag("accessibility"),
                extract: flag("extract"),
                modify_annotation: flag("modifyannotations"),
                modify_assembly: flag("modifyassembly"),
                modify_form: flag("modifyforms"),
                modify_other: flag("modifyother"),
                print_lowres: flag("printlow"),
                print_highres: flag("printhigh"),
            },
        })
    }

    /// Whether `/StmF`'s crypt filter is RC4 (`/V2`) or none, from `interpretCF` in qpdf's
    /// `QPDF_encryption.cc`.
    fn stream_crypt_filter(&self, dictionary: &Py) -> Result<String, Raised> {
        let document = self.document;
        let name = self.get(dictionary, "/StmF")?;
        let filters = self.get(dictionary, "/CF")?;
        if let Py::Object(object) = &name
            && document.kind(*object)? == Kind::Name
        {
            let name = String::from_utf8_lossy(&document.name(*object)?).into_owned();
            if name != "/Identity" {
                let filter = self.get(&filters, &name)?;
                if let Py::Object(cfm) = self.get(&filter, "/CFM")?
                    && document.kind(cfm)? == Kind::Name
                    && document.name(cfm)? == b"/V2"
                {
                    return Ok("rc4".to_owned());
                }
            }
        }
        Ok("none".to_owned())
    }

    /// `fix_page_tree_counts` in pikepdf's `qpdf.cpp`, which `pdf.save` runs, and which makes the
    /// `/Count`s of a saved file right.
    pub fn fix_page_tree_counts(&self) -> Result<(), Raised> {
        let document = self.document;
        let root = document.root()?;
        if let Some(pages) = document.key(root, "/Pages")?
            && document.kind(pages)? == Kind::Dictionary
        {
            let mut visited = BTreeSet::new();
            self.fix_counts(pages, &mut visited, 0)?;
        }
        Ok(())
    }

    fn fix_counts(
        &self,
        node: Handle,
        visited: &mut BTreeSet<(i32, i32)>,
        depth: u32,
    ) -> Result<i64, Raised> {
        let document = self.document;
        let id = document.id(node);
        if depth > 100 || (id.0 != 0 && !visited.insert(id)) {
            return Ok(0);
        }
        let mut count = 0;
        if let Some(kids) = document.key(node, "/Kids")?
            && document.kind(kids)? == Kind::Array
        {
            for i in 0..document.array_len(kids)? {
                let kid = document.array_item(kids, i)?;
                if document.kind(kid)? != Kind::Dictionary {
                    continue;
                }
                if document.key(kid, "/Kids")?.is_some() {
                    count += self.fix_counts(kid, visited, depth + 1)?;
                } else {
                    count += 1;
                }
            }
        }
        let current = match document.key(node, "/Count")? {
            Some(value) if document.kind(value)? == Kind::Integer => {
                Some(document.int_value(value)?)
            }
            _ => None,
        };
        if current != Some(count) {
            document.set_integer_key(node, c"/Count", count)?;
        }
        Ok(count)
    }
}

/// One annotation whose action opens a URI, as ace3's `iter_uri_annotations` yields it.
#[derive(Debug, Clone)]
pub struct UriAnnotation {
    /// The page's number, from 1.
    pub page_number: i32,
    pub page: Py,
    pub annot: Py,
    pub uri: Py,
}

/// `float(Decimal(text))` of a real as the file wrote it.
fn decimal_float(text: &[u8]) -> Result<f64, Raised> {
    String::from_utf8_lossy(text).parse::<f64>().map_err(|_| {
        Raised::new(
            "decimal.InvalidOperation",
            "[<class 'decimal.ConversionSyntax'>]",
        )
    })
}

/// `int(Decimal(text)) % 360 != 0`, for a real of any length: Python's int cuts the fraction off,
/// and no multiple of 360 depends on the sign.
pub fn decimal_turns_the_page(text: &[u8]) -> bool {
    let text = String::from_utf8_lossy(text);
    let whole = text.trim_start_matches(['+', '-']);
    let whole = whole.split('.').next().unwrap_or_default();
    whole
        .bytes()
        .filter(u8::is_ascii_digit)
        .fold(0u32, |rest, digit| {
            (rest * 10 + u32::from(digit - b'0')) % 360
        })
        != 0
}

/// `str(Decimal(text))`.
fn decimal_text(text: &[u8]) -> String {
    let text = String::from_utf8_lossy(text);
    let (sign, rest) = match text.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", text.strip_prefix('+').unwrap_or(&text)),
    };
    let (whole, fraction) = rest.split_once('.').unwrap_or((rest, ""));
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    if fraction.is_empty() {
        format!("{sign}{whole}")
    } else {
        format!("{sign}{whole}.{fraction}")
    }
}

/// `append_quoted` in pikepdf's `object_repr.cpp`.
fn quoted(out: &mut Vec<u8>, text: &[u8]) {
    out.push(b'"');
    for &byte in text {
        if byte == b'"' || byte == b'\\' {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b'"');
}

/// `{"base64": ...}`, as `ace_results::Bytes` writes it.
pub fn bytes_json(bytes: Vec<u8>) -> serde_json::Value {
    serde_json::to_value(ace_results::Bytes(bytes)).unwrap_or(serde_json::Value::Null)
}

pub use ace_results::types::pdf::{Encryption, Permissions};
