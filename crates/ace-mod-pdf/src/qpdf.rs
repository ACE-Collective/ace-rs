//! A small safe layer over libqpdf's C API, by way of `qpdf-sys`, the binding the qpdf crate is built
//! on. The crate's own wrapper can't be used here: it keeps its `qpdf_data` handle private and doesn't
//! expose `qpdf_set_newline_before_endstream` or `qpdf_push_inherited_attributes_to_page`, both of
//! which pikepdf calls and both of which change the bytes of a decrypted copy.
//!
//! libqpdf is C++, and an exception must not cross into Rust. Every call here is to libqpdf's C API,
//! whose functions catch `std::exception` (`trap_errors` and `trap_oh_errors` in `qpdf-c.cc`) and
//! record it for `qpdf_get_error`. libqpdf throws nothing else. It starts no threads and no processes,
//! so it runs under a task's seccomp filter, and needs no file but its input, because the vendored
//! build never opens `/dev/urandom` (`vendor/README.md`).

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use qpdf_sys as sys;

/// An exception as Python would report it, because that's what `tools/library-diff/run` compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raised {
    pub kind: String,
    pub message: String,
}

impl Raised {
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Raised {
            kind: kind.to_owned(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Raised {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

/// The type of a PDF object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Null,
    Bool,
    Integer,
    Real,
    String,
    Name,
    Array,
    Dictionary,
    Stream,
    /// Nothing a file's objects are: an operator exists only in a parsed content stream.
    Other,
}

/// An object handle, good for as long as its `Document`.
pub type Handle = sys::qpdf_oh;

/// An open PDF.
pub struct Document {
    data: sys::qpdf_data,
    path: String,
}

impl Drop for Document {
    fn drop(&mut self) {
        // SAFETY: `data` came from qpdf_init and is cleaned up only here. An error still pending
        // would be logged by qpdf_cleanup, so it's taken first.
        unsafe {
            while sys::qpdf_has_error(self.data) != 0 {
                sys::qpdf_get_error(self.data);
            }
            sys::qpdf_cleanup(&mut self.data);
        }
    }
}

fn c_path(path: &Path) -> Result<CString, Raised> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Raised::new("ValueError", "embedded null byte"))
}

impl Document {
    /// `pikepdf.open(path)`: the empty password, recovery on, and the page tree's inherited
    /// attributes pushed down to the pages.
    pub fn open(path: &Path) -> Result<Document, Raised> {
        Document::open_with_password(path, c"")
    }

    /// `pikepdf.open(path, password=password)`, as `open`.
    pub fn open_with_password(path: &Path, password: &CStr) -> Result<Document, Raised> {
        let document = Document::read(path, password)?;
        document.check()?;
        // SAFETY: the document has been read.
        unsafe {
            sys::qpdf_push_inherited_attributes_to_page(document.data);
        }
        document.check()?;
        Ok(document)
    }

    /// A handle that has read the file with `password`, or tried to: the error, if any, is left for
    /// `check`.
    fn read(path: &Path, password: &CStr) -> Result<Document, Raised> {
        let name = c_path(path)?;
        // SAFETY: the handle is new, and the strings outlive the call, which copies them.
        let document = unsafe {
            let data = sys::qpdf_init();
            sys::qpdf_silence_errors(data);
            sys::qpdf_set_suppress_warnings(data, 1);
            Document {
                data,
                path: path.to_string_lossy().into_owned(),
            }
        };
        // SAFETY: as above.
        unsafe {
            sys::qpdf_read(document.data, name.as_ptr(), password.as_ptr());
        }
        Ok(document)
    }

    /// The standard security handler's parameters of a file the empty password doesn't open, as
    /// pdf2john.pl reads them for John: None when the file opens without one. libqpdf has read the
    /// trailer and the `/Encrypt` dictionary by the time it finds the password wrong, and keeps them:
    /// it reads `/Encrypt` while the file isn't yet known to be encrypted, so its strings are as the
    /// file has them.
    pub fn locked(path: &Path) -> Result<Option<Locked>, Raised> {
        let document = Document::read(path, c"")?;
        match document.check() {
            Ok(()) => return Ok(None),
            Err(raised) if raised.kind == "PasswordError" => {}
            Err(raised) => return Err(raised),
        }
        let trailer = document.trailer()?;
        let mut id = Vec::new();
        if let Some(ids) = document.key(trailer, "/ID")?
            && document.kind(ids)? == Kind::Array
            && document.array_len(ids)? >= 1
        {
            let first = document.array_item(ids, 0)?;
            if document.kind(first)? == Kind::String {
                id = document.string_bytes(first)?;
            }
        }
        let Some(encrypt) = document.key(trailer, "/Encrypt")? else {
            return Err(Raised::new("PdfError", "no /Encrypt in the trailer"));
        };
        let integer = |key: &str| -> Result<Option<i64>, Raised> {
            match document.key(encrypt, key)? {
                Some(value) if document.kind(value)? == Kind::Integer => {
                    document.int_value(value).map(Some)
                }
                _ => Ok(None),
            }
        };
        let string = |key: &str| -> Result<Option<Vec<u8>>, Raised> {
            match document.key(encrypt, key)? {
                Some(value) if document.kind(value)? == Kind::String => {
                    document.string_bytes(value).map(Some)
                }
                _ => Ok(None),
            }
        };
        let encrypt_metadata = match document.key(encrypt, "/EncryptMetadata")? {
            Some(value) if document.kind(value)? == Kind::Bool => Some(document.bool_value(value)?),
            _ => None,
        };
        Ok(Some(Locked {
            v: integer("/V")?,
            r: integer("/R")?,
            length: integer("/Length")?,
            p: integer("/P")?,
            o: string("/O")?,
            u: string("/U")?,
            encrypt_metadata,
            id,
        }))
    }

    /// The exception libqpdf last caught, as pikepdf's translator would raise it.
    pub fn check(&self) -> Result<(), Raised> {
        // SAFETY: the handle is live. An error stays valid until the next API call that sets one,
        // and its text is copied before anything else is called.
        unsafe {
            if sys::qpdf_has_error(self.data) == 0 {
                return Ok(());
            }
            let error = sys::qpdf_get_error(self.data);
            let code = sys::qpdf_get_error_code(self.data, error);
            let text = sys::qpdf_get_error_full_text(self.data, error);
            let message = if text.is_null() {
                String::new()
            } else {
                CStr::from_ptr(text).to_string_lossy().into_owned()
            };
            let kind = if code == sys::qpdf_error_code_e_qpdf_e_password {
                "PasswordError"
            } else {
                "PdfError"
            };
            Err(Raised::new(kind, message))
        }
    }

    pub fn is_encrypted(&self) -> bool {
        // SAFETY: the handle is live.
        unsafe { sys::qpdf_is_encrypted(self.data) != 0 }
    }

    /// The number of pages, loading the page tree.
    pub fn page_count(&self) -> Result<i32, Raised> {
        // SAFETY: the handle is live.
        let count = unsafe { sys::qpdf_get_num_pages(self.data) };
        self.check()?;
        Ok(count)
    }

    pub fn page(&self, index: i32) -> Result<Handle, Raised> {
        // SAFETY: the handle is live, and a bad index is an error it reports.
        let page = unsafe { sys::qpdf_get_page_n(self.data, index as usize) };
        self.check()?;
        Ok(page)
    }

    pub fn root(&self) -> Result<Handle, Raised> {
        // SAFETY: the handle is live.
        let root = unsafe { sys::qpdf_get_root(self.data) };
        self.check()?;
        Ok(root)
    }

    pub fn trailer(&self) -> Result<Handle, Raised> {
        // SAFETY: the handle is live.
        let trailer = unsafe { sys::qpdf_get_trailer(self.data) };
        self.check()?;
        Ok(trailer)
    }

    pub fn kind(&self, object: Handle) -> Result<Kind, Raised> {
        // SAFETY: handles come from this document.
        let code = unsafe { sys::qpdf_oh_get_type_code(self.data, object) };
        self.check()?;
        #[allow(non_upper_case_globals)]
        Ok(match code {
            sys::qpdf_object_type_e_ot_null => Kind::Null,
            sys::qpdf_object_type_e_ot_boolean => Kind::Bool,
            sys::qpdf_object_type_e_ot_integer => Kind::Integer,
            sys::qpdf_object_type_e_ot_real => Kind::Real,
            sys::qpdf_object_type_e_ot_string => Kind::String,
            sys::qpdf_object_type_e_ot_name => Kind::Name,
            sys::qpdf_object_type_e_ot_array => Kind::Array,
            sys::qpdf_object_type_e_ot_dictionary => Kind::Dictionary,
            sys::qpdf_object_type_e_ot_stream => Kind::Stream,
            _ => Kind::Other,
        })
    }

    /// `object`'s value at `key` when `object` is a dictionary or a stream's dictionary and has it.
    /// libqpdf treats a key whose value is null as absent.
    pub fn key(&self, object: Handle, key: &str) -> Result<Option<Handle>, Raised> {
        let dictionary = match self.kind(object)? {
            Kind::Dictionary => object,
            // SAFETY: a stream has a dictionary.
            Kind::Stream => unsafe { sys::qpdf_oh_get_dict(self.data, object) },
            _ => return Ok(None),
        };
        let key = CString::new(key).map_err(|_| Raised::new("ValueError", "embedded null byte"))?;
        // SAFETY: the key outlives the calls, which copy it.
        unsafe {
            if sys::qpdf_oh_has_key(self.data, dictionary, key.as_ptr()) == 0 {
                self.check()?;
                return Ok(None);
            }
            let value = sys::qpdf_oh_get_key(self.data, dictionary, key.as_ptr());
            self.check()?;
            Ok(Some(value))
        }
    }

    /// The keys of a dictionary, or of a stream's dictionary, sorted as libqpdf keeps them.
    pub fn keys(&self, object: Handle) -> Result<Vec<Vec<u8>>, Raised> {
        let dictionary = match self.kind(object)? {
            Kind::Dictionary => object,
            // SAFETY: a stream has a dictionary.
            Kind::Stream => unsafe { sys::qpdf_oh_get_dict(self.data, object) },
            _ => return Ok(Vec::new()),
        };
        let mut keys = Vec::new();
        // SAFETY: the key each call returns is copied before the next call replaces it.
        unsafe {
            sys::qpdf_oh_begin_dict_key_iter(self.data, dictionary);
            while sys::qpdf_oh_dict_more_keys(self.data) != 0 {
                let key = sys::qpdf_oh_dict_next_key(self.data);
                keys.push(CStr::from_ptr(key).to_bytes().to_vec());
            }
        }
        self.check()?;
        Ok(keys)
    }

    pub fn array_len(&self, object: Handle) -> Result<i32, Raised> {
        // SAFETY: handles come from this document.
        let len = unsafe { sys::qpdf_oh_get_array_n_items(self.data, object) };
        self.check()?;
        Ok(len)
    }

    pub fn array_item(&self, object: Handle, index: i32) -> Result<Handle, Raised> {
        // SAFETY: handles come from this document.
        let item = unsafe { sys::qpdf_oh_get_array_item(self.data, object, index) };
        self.check()?;
        Ok(item)
    }

    /// Gives a handle back. libqpdf keeps every handle it hands out until the document closes, so
    /// a loop over a file's own count of things releases what each turn made, or a few MB of
    /// repeated references become gigabytes of handles.
    pub fn release(&self, object: Handle) {
        // SAFETY: the handle came from this document, and nothing uses it after.
        unsafe { sys::qpdf_oh_release(self.data, object) }
    }

    /// (object id, generation); (0, 0) for a direct object.
    pub fn id(&self, object: Handle) -> (i32, i32) {
        // SAFETY: handles come from this document.
        unsafe {
            (
                sys::qpdf_oh_get_object_id(self.data, object),
                sys::qpdf_oh_get_generation(self.data, object),
            )
        }
    }

    pub fn bool_value(&self, object: Handle) -> Result<bool, Raised> {
        // SAFETY: handles come from this document.
        let value = unsafe { sys::qpdf_oh_get_bool_value(self.data, object) };
        self.check()?;
        Ok(value != 0)
    }

    pub fn int_value(&self, object: Handle) -> Result<i64, Raised> {
        // SAFETY: handles come from this document.
        let value = unsafe { sys::qpdf_oh_get_int_value(self.data, object) };
        self.check()?;
        Ok(value)
    }

    /// Copies what a call left in libqpdf's string buffer, which may hold NULs.
    fn copied(&self, pointer: *const c_char, length: usize) -> Result<Vec<u8>, Raised> {
        self.check()?;
        if pointer.is_null() {
            return Ok(Vec::new());
        }
        // SAFETY: libqpdf says `pointer` holds `length` bytes until its next string call.
        Ok(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) }.to_vec())
    }

    /// A real number's text, as the file has it.
    pub fn real_value(&self, object: Handle) -> Result<Vec<u8>, Raised> {
        // SAFETY: handles come from this document, and the length is read before another call.
        unsafe {
            let pointer = sys::qpdf_oh_get_real_value(self.data, object);
            let length = sys::qpdf_get_last_string_length(self.data);
            self.copied(pointer, length)
        }
    }

    /// A name, with its `/`, and `#xx` decoded.
    pub fn name(&self, object: Handle) -> Result<Vec<u8>, Raised> {
        // SAFETY: as in `real_value`.
        unsafe {
            let pointer = sys::qpdf_oh_get_name(self.data, object);
            let length = sys::qpdf_get_last_string_length(self.data);
            self.copied(pointer, length)
        }
    }

    /// A string's bytes.
    pub fn string_bytes(&self, object: Handle) -> Result<Vec<u8>, Raised> {
        let mut length = 0;
        // SAFETY: as in `real_value`.
        let pointer =
            unsafe { sys::qpdf_oh_get_binary_string_value(self.data, object, &mut length) };
        self.copied(pointer, length)
    }

    /// A string as UTF-8: `QPDFObjectHandle::getUTF8Value`, which reads UTF-16 and PDFDocEncoding.
    pub fn string_utf8(&self, object: Handle) -> Result<Vec<u8>, Raised> {
        let mut length = 0;
        // SAFETY: as in `real_value`.
        let pointer = unsafe { sys::qpdf_oh_get_binary_utf8_value(self.data, object, &mut length) };
        self.copied(pointer, length)
    }

    /// A stream's data through its general filters, as pikepdf's `read_bytes()`, including how it
    /// reports a failure: libqpdf records why a filter failed as a warning, and pikepdf looks there.
    /// It raises on a filter libqpdf doesn't apply at this level, such as DCTDecode, where the C API
    /// returns the raw bytes and says so.
    pub fn stream_data(&self, object: Handle) -> Result<Vec<u8>, Raised> {
        let (id, generation) = self.id(object);
        let mut filtered = 0;
        let mut buffer = std::ptr::null_mut();
        let mut length = 0;
        // SAFETY: libqpdf allocates `buffer` with malloc on success, and it's freed here. A warning
        // stays valid until the next one is taken, and is copied first.
        unsafe {
            while sys::qpdf_more_warnings(self.data) != 0 {
                sys::qpdf_next_warning(self.data);
            }
            sys::qpdf_oh_get_stream_data(
                self.data,
                object,
                sys::qpdf_stream_decode_level_e_qpdf_dl_generalized,
                &mut filtered,
                &mut buffer,
                &mut length,
            );
            let result = self.check();
            let bytes = if buffer.is_null() {
                Vec::new()
            } else {
                let bytes = std::slice::from_raw_parts(buffer, length).to_vec();
                libc::free(buffer.cast::<c_void>());
                bytes
            };
            if result.is_err() {
                let prefix = format!("error decoding stream data for object {id} {generation}: ");
                while sys::qpdf_more_warnings(self.data) != 0 {
                    let warning = sys::qpdf_next_warning(self.data);
                    let detail = sys::qpdf_get_error_message_detail(self.data, warning);
                    if detail.is_null() {
                        continue;
                    }
                    let detail = CStr::from_ptr(detail).to_string_lossy();
                    if let Some(cause) = detail.strip_prefix(prefix.as_str()) {
                        let file = sys::qpdf_get_error_filename(self.data, warning);
                        let file = if file.is_null() {
                            String::new()
                        } else {
                            CStr::from_ptr(file).to_string_lossy().into_owned()
                        };
                        let position = sys::qpdf_get_error_file_position(self.data, warning);
                        return Err(Raised::new(
                            "DataDecodingError",
                            format!(
                                "{file} (object {id},{generation}, offset {position}): {cause}"
                            ),
                        ));
                    }
                }
            }
            result?;
            if filtered == 0 {
                let file = &self.path;
                return Err(Raised::new(
                    "PdfError",
                    format!(
                        "{file} (object {id},{generation}): read_bytes called on unfilterable stream"
                    ),
                ));
            }
            Ok(bytes)
        }
    }

    pub fn is_dictionary_of_type(&self, object: Handle, kind: &CStr) -> Result<bool, Raised> {
        // SAFETY: the strings outlive the call.
        let is = unsafe {
            sys::qpdf_oh_is_dictionary_of_type(self.data, object, kind.as_ptr(), c"".as_ptr())
        };
        self.check()?;
        Ok(is != 0)
    }

    /// `QPDFObjectHandle::replaceKey` with an integer, for `fix_page_tree_counts`.
    pub fn set_integer_key(&self, object: Handle, key: &CStr, value: i64) -> Result<(), Raised> {
        // SAFETY: the strings outlive the call.
        unsafe {
            let integer = sys::qpdf_oh_new_integer(self.data, value);
            sys::qpdf_oh_replace_key(self.data, object, key.as_ptr(), integer);
        }
        self.check()
    }

    /// `pdf.save(fp, stream_decode_level=none, compress_streams=False, deterministic_id=True)`: no
    /// encryption, streams left as they are, newlines before `endstream` (pikepdf's
    /// `preserve_pdfa`) and an `/ID` from the content. A stream isn't decoded here, so this does no
    /// more than copy a file's bytes.
    pub fn save_decrypted(&self) -> Result<Vec<u8>, Raised> {
        // SAFETY: the buffer stays valid until the next write or the cleanup, and is copied.
        unsafe {
            sys::qpdf_init_write_memory(self.data);
            self.check()?;
            sys::qpdf_set_deterministic_ID(self.data, 1);
            sys::qpdf_set_newline_before_endstream(self.data, 1);
            sys::qpdf_set_compress_streams(self.data, 0);
            sys::qpdf_set_decode_level(self.data, sys::qpdf_stream_decode_level_e_qpdf_dl_none);
            sys::qpdf_set_object_stream_mode(self.data, sys::qpdf_object_stream_e_qpdf_o_preserve);
            sys::qpdf_set_preserve_encryption(self.data, 0);
            sys::qpdf_set_content_normalization(self.data, 0);
            sys::qpdf_set_linearization(self.data, 0);
            sys::qpdf_set_qdf_mode(self.data, 0);
            self.check()?;
            sys::qpdf_write(self.data);
            self.check()?;
            let length = sys::qpdf_get_buffer_length(self.data);
            let buffer = sys::qpdf_get_buffer(self.data);
            if buffer.is_null() {
                return Ok(Vec::new());
            }
            Ok(std::slice::from_raw_parts(buffer, length).to_vec())
        }
    }
}

impl Document {
    /// `pdf.save(fp)` with pikepdf's defaults: no encryption, streams compressed, those with
    /// generalized filters decoded first, newlines before `endstream`, object streams as they are. But
    /// for one thing: pikepdf makes the second `/ID` from the clock, and this makes it from the
    /// content, as `deterministic_id=True` does, so the same file gives the same bytes. pikepdf's
    /// `fix_metadata_version` rewrites the XMP of a file that has some, which this doesn't.
    pub fn save_as_pikepdf_saves(&self) -> Result<Vec<u8>, Raised> {
        // SAFETY: the buffer stays valid until the next write or the cleanup, and is copied.
        unsafe {
            sys::qpdf_init_write_memory(self.data);
            self.check()?;
            sys::qpdf_set_deterministic_ID(self.data, 1);
            sys::qpdf_set_newline_before_endstream(self.data, 1);
            sys::qpdf_set_compress_streams(self.data, 1);
            sys::qpdf_set_object_stream_mode(self.data, sys::qpdf_object_stream_e_qpdf_o_preserve);
            sys::qpdf_set_preserve_encryption(self.data, 0);
            sys::qpdf_set_content_normalization(self.data, 0);
            sys::qpdf_set_linearization(self.data, 0);
            sys::qpdf_set_qdf_mode(self.data, 0);
            self.check()?;
            sys::qpdf_write(self.data);
            self.check()?;
            let length = sys::qpdf_get_buffer_length(self.data);
            let buffer = sys::qpdf_get_buffer(self.data);
            if buffer.is_null() {
                return Ok(Vec::new());
            }
            Ok(std::slice::from_raw_parts(buffer, length).to_vec())
        }
    }
}

/// What pdf2john.pl reads from a locked file's `/Encrypt` dictionary and trailer, each as the file
/// has it, None when it's missing or of another type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locked {
    pub v: Option<i64>,
    pub r: Option<i64>,
    pub length: Option<i64>,
    pub p: Option<i64>,
    pub o: Option<Vec<u8>>,
    pub u: Option<Vec<u8>>,
    pub encrypt_metadata: Option<bool>,
    /// The first string of the trailer's `/ID`, or nothing.
    pub id: Vec<u8>,
}

// qpdfjob-c.h, which the crate's bindings leave out and its build compiles.
unsafe extern "C" {
    fn qpdfjob_init() -> *mut c_void;
    fn qpdfjob_cleanup(job: *mut *mut c_void);
    fn qpdfjob_set_logger(job: *mut c_void, logger: sys::qpdflogger_handle);
    fn qpdfjob_initialize_from_argv(job: *mut c_void, argv: *const *const c_char) -> c_int;
    fn qpdfjob_run(job: *mut c_void) -> c_int;
}

/// Gathers what a job writes.
unsafe extern "C" fn gather(data: *const c_char, length: usize, udata: *mut c_void) -> c_int {
    if !data.is_null() && !udata.is_null() {
        // SAFETY: `udata` is the Vec in `encryption_json`, which outlives the job, and libqpdf says
        // `data` holds `length` bytes. Extending a Vec panics only when allocation aborts anyway.
        unsafe {
            (*udata.cast::<Vec<u8>>())
                .extend_from_slice(std::slice::from_raw_parts(data.cast::<u8>(), length));
        }
    }
    0
}

/// `qpdf --json=2 --json-key=encrypt`, on the file at `path`, with the empty password: libqpdf's C
/// API has neither the encryption key's length, nor the stream's method, nor whether the password
/// matched the owner's. The job's code does, and it's the same library reading the same file.
pub fn encryption_json(path: &Path) -> Result<serde_json::Value, Raised> {
    let name = c_path(path)?;
    let mut output: Vec<u8> = Vec::new();
    let argv = [
        c"qpdf".as_ptr(),
        c"--json=2".as_ptr(),
        c"--json-key=encrypt".as_ptr(),
        name.as_ptr(),
        std::ptr::null(),
    ];
    // SAFETY: argv and the output outlive the job, which is cleaned up here, and the logger after it.
    unsafe {
        let mut job = qpdfjob_init();
        let mut logger = sys::qpdflogger_create();
        // the JSON is the job's saved output, which would go to stdout
        sys::qpdflogger_set_save(
            logger,
            sys::qpdf_log_dest_e_qpdf_log_dest_custom,
            Some(gather),
            (&raw mut output).cast::<c_void>(),
            0,
        );
        sys::qpdflogger_set_info(
            logger,
            sys::qpdf_log_dest_e_qpdf_log_dest_discard,
            None,
            std::ptr::null_mut(),
        );
        sys::qpdflogger_set_warn(
            logger,
            sys::qpdf_log_dest_e_qpdf_log_dest_discard,
            None,
            std::ptr::null_mut(),
        );
        sys::qpdflogger_set_error(
            logger,
            sys::qpdf_log_dest_e_qpdf_log_dest_discard,
            None,
            std::ptr::null_mut(),
        );
        qpdfjob_set_logger(job, logger);
        let started = qpdfjob_initialize_from_argv(job, argv.as_ptr());
        if started == 0 {
            qpdfjob_run(job);
        }
        qpdfjob_cleanup(&mut job);
        sys::qpdflogger_cleanup(&mut logger);
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output)
        .map_err(|e| Raised::new("PdfError", format!("reading qpdf's encryption JSON: {e}")))?;
    parsed
        .get("encrypt")
        .cloned()
        .ok_or_else(|| Raised::new("PdfError", "qpdf's JSON has no encrypt key"))
}
