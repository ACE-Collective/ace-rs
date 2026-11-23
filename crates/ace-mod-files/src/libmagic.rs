//! libmagic, as ace3's `file -b -L` and `file -b --mime-type -L` run it.
//!
//! The database is read before containment, which can't open it, and a cookie is made from those
//! bytes in the task. libmagic and the database are the ones ace3's image has, 5.46 (the dev image
//! and `docker/ace-rs/Dockerfile` pin both). `file` opens the file by its path, and so does
//! `magic_file` here: by a descriptor or a buffer libmagic answers some files differently, an empty
//! file's mime type among them.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// libmagic's API, as magic.h declares it; the library is linked by magic-sys.
#[allow(non_camel_case_types)]
type magic_t = *mut c_void;

unsafe extern "C" {
    fn magic_open(flags: c_int) -> magic_t;
    fn magic_close(cookie: magic_t);
    fn magic_error(cookie: magic_t) -> *const c_char;
    fn magic_file(cookie: magic_t, path: *const c_char) -> *const c_char;
    fn magic_load_buffers(
        cookie: magic_t,
        buffers: *mut *mut c_void,
        sizes: *mut usize,
        count: usize,
    ) -> c_int;
}

use magic_sys as _;

/// `-L`: follow symbolic links.
const MAGIC_SYMLINK: c_int = 0x0000002;
/// `--mime-type`.
const MAGIC_MIME_TYPE: c_int = 0x0000010;

/// Where ace-rs's images keep the database, the one `file` reads in ace3's image.
pub const DATABASE: &str = "/usr/lib/file/magic.mgc";

/// What `file` prints: the description, or its mime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Description,
    MimeType,
}

/// libmagic with a database loaded. Not shared between threads.
pub struct Magic {
    cookie: magic_t,
    // libmagic keeps pointers into the buffer it loaded
    _database: Box<[u8]>,
}

impl Drop for Magic {
    fn drop(&mut self) {
        unsafe { magic_close(self.cookie) };
    }
}

impl Magic {
    /// A cookie over a database's bytes, read before containment.
    pub fn load(database: &[u8], answer: Answer) -> Result<Magic, String> {
        let flags = match answer {
            Answer::Description => MAGIC_SYMLINK,
            Answer::MimeType => MAGIC_SYMLINK | MAGIC_MIME_TYPE,
        };
        let mut database: Box<[u8]> = database.into();
        unsafe {
            let cookie = magic_open(flags);
            if cookie.is_null() {
                return Err("magic_open failed".to_owned());
            }
            let mut buffers = [database.as_mut_ptr() as *mut c_void];
            let mut sizes = [database.len()];
            if magic_load_buffers(cookie, buffers.as_mut_ptr(), sizes.as_mut_ptr(), 1) != 0 {
                let error = error_text(cookie);
                magic_close(cookie);
                return Err(format!("magic_load_buffers failed: {error}"));
            }
            Ok(Magic {
                cookie,
                _database: database,
            })
        }
    }

    /// What `file -b` prints for the file, without its newline: libmagic's answer, or `ERROR: `
    /// and libmagic's error when it has none.
    pub fn file(&self, path: &Path) -> String {
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return "ERROR: the path holds a NUL".to_owned();
        };
        unsafe {
            let result = magic_file(self.cookie, path.as_ptr());
            if result.is_null() {
                return format!("ERROR: {}", error_text(self.cookie));
            }
            String::from_utf8_lossy(CStr::from_ptr(result).to_bytes()).into_owned()
        }
    }
}

unsafe fn error_text(cookie: magic_t) -> String {
    let error = unsafe { magic_error(cookie) };
    if error.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { CStr::from_ptr(error) }.to_bytes()).into_owned()
}
