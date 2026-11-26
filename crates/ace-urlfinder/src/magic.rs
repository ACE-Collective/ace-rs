//! `magic.from_buffer(blob)` of python-magic 0.4.27: libmagic's description of the bytes, with
//! no flags and the name/use limit raised to 64, as its `Magic()` sets it.
//!
//! A contained task can't open the database, so a module opens it before containment
//! (`Database::open`) and reads it through that descriptor only when a task needs libmagic, which
//! Landlock allows, since it checks a file only when it is opened. A cookie is made from those
//! bytes in the task. libmagic is the one ace3's image has, 5.46, and the
//! database is the same file (`docker/ace-rs/Dockerfile` pins both).

use std::ffi::{CStr, c_char, c_int, c_void};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use ace_pycompat::PyErr;

// libmagic's API, as magic.h declares it; the library is linked by magic-sys.
#[allow(non_camel_case_types)]
type magic_t = *mut c_void;

unsafe extern "C" {
    fn magic_open(flags: c_int) -> magic_t;
    fn magic_close(cookie: magic_t);
    fn magic_error(cookie: magic_t) -> *const c_char;
    fn magic_buffer(cookie: magic_t, buffer: *const c_void, length: usize) -> *const c_char;
    fn magic_load_buffers(
        cookie: magic_t,
        buffers: *mut *mut c_void,
        sizes: *mut usize,
        count: usize,
    ) -> c_int;
    fn magic_setparam(cookie: magic_t, param: c_int, value: *const c_void) -> c_int;
}

// keep the linker's view of magic-sys, which carries the `-lmagic`
use magic_sys as _;

const MAGIC_NONE: c_int = 0;
const MAGIC_PARAM_NAME_MAX: c_int = 1;

/// Where ace-rs's images keep the database, the one ace3's python-magic loads by default.
pub const DATABASE: &str = "/usr/lib/file/magic.mgc";

/// libmagic's database, opened before containment and read only when a task loads libmagic: most
/// tasks give urlfinderlib a description of their bytes, and never do.
pub struct Database {
    path: PathBuf,
    file: Result<File, String>,
}

impl Database {
    /// The database at `path`; a module's `init` passes [`DATABASE`]. A file that won't open is
    /// an error only for a task that loads libmagic.
    pub fn open(path: &Path) -> Database {
        Database {
            path: path.to_owned(),
            file: File::open(path).map_err(|e| format!("{}: {e}", path.display())),
        }
    }

    /// libmagic over the database's bytes, read through the descriptor opened before containment.
    /// `read_exact_at` keeps no file position, so concurrent tasks of one module can share it.
    pub fn load(&self) -> Result<Magic, String> {
        let file = self.file.as_ref().map_err(Clone::clone)?;
        let read = || -> std::io::Result<Vec<u8>> {
            let mut bytes = vec![0; usize::try_from(file.metadata()?.len()).unwrap_or(usize::MAX)];
            file.read_exact_at(&mut bytes, 0)?;
            Ok(bytes)
        };
        let bytes = read().map_err(|e| format!("reading {}: {e}", self.path.display()))?;
        Magic::load(bytes)
    }
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
    pub fn load(database: Vec<u8>) -> Result<Magic, String> {
        let mut database = database.into_boxed_slice();
        unsafe {
            let cookie = magic_open(MAGIC_NONE);
            if cookie.is_null() {
                return Err("magic_open failed".to_owned());
            }
            let mut buffers = [database.as_mut_ptr() as *mut c_void];
            let mut sizes = [database.len()];
            if magic_load_buffers(cookie, buffers.as_mut_ptr(), sizes.as_mut_ptr(), 1) != 0 {
                let error = error_text(cookie).unwrap_or_default();
                magic_close(cookie);
                return Err(format!("magic_load_buffers failed: {error}"));
            }
            // python-magic ignores a failure here
            let name_max: usize = 64;
            magic_setparam(
                cookie,
                MAGIC_PARAM_NAME_MAX,
                &name_max as *const usize as *const c_void,
            );
            Ok(Magic {
                cookie,
                _database: database,
            })
        }
    }

    /// `magic.from_buffer(blob)`: the description, decoded as UTF-8 with backslashreplace; a
    /// libmagic error is python-magic's MagicException.
    pub fn from_buffer(&self, blob: &[u8]) -> Result<String, PyErr> {
        unsafe {
            let result = magic_buffer(self.cookie, blob.as_ptr() as *const c_void, blob.len());
            if result.is_null() {
                let message = error_text(self.cookie).unwrap_or_else(|| "None".to_owned());
                return Err(PyErr::new("magic", "MagicException", message));
            }
            Ok(backslashreplace(CStr::from_ptr(result).to_bytes()))
        }
    }
}

unsafe fn error_text(cookie: magic_t) -> Option<String> {
    let error = unsafe { magic_error(cookie) };
    (!error.is_null()).then(|| backslashreplace(unsafe { CStr::from_ptr(error) }.to_bytes()))
}

/// `bytes.decode("utf-8", "backslashreplace")`.
fn backslashreplace(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for b in chunk.invalid() {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}
