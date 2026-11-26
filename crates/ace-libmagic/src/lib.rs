//! libmagic's compiled database, mapped read-only, and cookies that load from it without a copy.
//!
//! A contained task can't open the database, so a module maps it before containment
//! (`Database::open`); Landlock checks a file only when it is opened, so the mapping still reads
//! afterwards. A cookie borrows the bytes it loads, since libmagic keeps pointers into them, and
//! reads only the pages it matches against, so a task reads few of the database's 10 MB.
//!
//! This is the mapping and the cookie alone, shared by the two crates that ask libmagic their own
//! way: `ace-mod-files`' type step, as `file` does, and `ace-urlfinder`, as python-magic does.
//! Neither can depend on the other without taking in its dependencies. libmagic and the database
//! are 5.46, ace3's (the dev image and `docker/ace-rs/Dockerfile` pin both).

use std::ffi::{CStr, c_char, c_int, c_void};
use std::fs::File;
use std::marker::PhantomData;
use std::path::Path;

// libmagic's API, as magic.h declares it; the library is linked by magic-sys.
#[allow(non_camel_case_types)]
type magic_t = *mut c_void;

unsafe extern "C" {
    fn magic_open(flags: c_int) -> magic_t;
    fn magic_close(cookie: magic_t);
    fn magic_error(cookie: magic_t) -> *const c_char;
    fn magic_file(cookie: magic_t, path: *const c_char) -> *const c_char;
    fn magic_buffer(cookie: magic_t, buffer: *const c_void, length: usize) -> *const c_char;
    fn magic_load_buffers(
        cookie: magic_t,
        buffers: *mut *mut c_void,
        sizes: *mut usize,
        count: usize,
    ) -> c_int;
    fn magic_setparam(cookie: magic_t, param: c_int, value: *const c_void) -> c_int;
}

use magic_sys as _;

/// No flags: the description.
pub const MAGIC_NONE: c_int = 0x0000000;
/// `file -L`: follow symbolic links.
pub const MAGIC_SYMLINK: c_int = 0x0000002;
/// `file --mime-type`.
pub const MAGIC_MIME_TYPE: c_int = 0x0000010;
/// `magic_setparam`'s limit on name/use recursion.
pub const MAGIC_PARAM_NAME_MAX: c_int = 1;

/// Where ace-rs's images keep the database, the one ace3's `file` and python-magic read.
pub const DATABASE: &str = "/usr/lib/file/magic.mgc";

/// The first word of a compiled database, file.h's `MAGICNO`, in the order libmagic reads it.
const MAGICNO: u32 = 0xF11E_041C;

/// Whether `bytes` start as a compiled database in this machine's byte order. libmagic swaps a
/// database of the other order in place, which would write to bytes a cookie only borrows; one in
/// this order it only reads (apprentice.c's check_buffer).
fn in_this_byte_order(bytes: &[u8]) -> bool {
    bytes
        .get(..4)
        .is_some_and(|word| u32::from_ne_bytes(word.try_into().expect("four bytes")) == MAGICNO)
}

/// libmagic's compiled database, mapped read-only. Every cookie made from it borrows it, so the
/// mapping outlives the pointers libmagic keeps into it.
pub struct Database {
    map: memmap2::Mmap,
}

impl Database {
    /// Maps the database at `path`, before containment.
    pub fn open(path: &Path) -> Result<Database, String> {
        let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        // SAFETY: the mapping is read-only, and its bytes change only if the file does; the
        // database is the image's own, which nothing writes or truncates while a task runs.
        let map = unsafe { memmap2::Mmap::map(&file) }
            .map_err(|e| format!("mapping {}: {e}", path.display()))?;
        if !in_this_byte_order(&map) {
            return Err(format!(
                "{}: not a compiled libmagic database in this machine's byte order",
                path.display()
            ));
        }
        Ok(Database { map })
    }

    /// The database's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.map
    }
}

/// A libmagic cookie with a database loaded, borrowing its bytes. Not shared between threads.
pub struct Cookie<'d> {
    cookie: magic_t,
    _database: PhantomData<&'d [u8]>,
}

impl Drop for Cookie<'_> {
    fn drop(&mut self) {
        unsafe { magic_close(self.cookie) };
    }
}

/// libmagic's answer, or its error text when it has none (None when it gives no text either).
pub type Answer = Result<Vec<u8>, Option<Vec<u8>>>;

impl<'d> Cookie<'d> {
    /// A cookie with these flags over a compiled database's bytes, which it borrows: a
    /// [`Database`]'s mapping, or a copy.
    pub fn load(database: &'d [u8], flags: c_int) -> Result<Cookie<'d>, String> {
        if !in_this_byte_order(database) {
            return Err("not a compiled libmagic database in this machine's byte order".to_owned());
        }
        unsafe {
            let cookie = magic_open(flags);
            if cookie.is_null() {
                return Err("magic_open failed".to_owned());
            }
            let cookie = Cookie {
                cookie,
                _database: PhantomData,
            };
            // magic.h's signature takes mutable buffers, but libmagic writes to one only to swap
            // its byte order, which was checked above
            let mut buffers = [database.as_ptr() as *mut c_void];
            let mut sizes = [database.len()];
            if magic_load_buffers(cookie.cookie, buffers.as_mut_ptr(), sizes.as_mut_ptr(), 1) != 0 {
                let error = cookie.error().unwrap_or_default();
                return Err(format!(
                    "magic_load_buffers failed: {}",
                    String::from_utf8_lossy(&error)
                ));
            }
            Ok(cookie)
        }
    }

    /// `magic_setparam`: whether libmagic took the value.
    pub fn set_param(&self, param: c_int, value: usize) -> bool {
        unsafe { magic_setparam(self.cookie, param, &value as *const usize as *const c_void) == 0 }
    }

    /// `magic_file`: libmagic opens the file by its path.
    pub fn file(&self, path: &CStr) -> Answer {
        let result = unsafe { magic_file(self.cookie, path.as_ptr()) };
        self.answer(result)
    }

    /// `magic_buffer`: the bytes themselves.
    pub fn buffer(&self, bytes: &[u8]) -> Answer {
        let result =
            unsafe { magic_buffer(self.cookie, bytes.as_ptr() as *const c_void, bytes.len()) };
        self.answer(result)
    }

    fn answer(&self, result: *const c_char) -> Answer {
        if result.is_null() {
            return Err(self.error());
        }
        Ok(unsafe { CStr::from_ptr(result) }.to_bytes().to_vec())
    }

    /// `magic_error`'s text.
    fn error(&self) -> Option<Vec<u8>> {
        let error = unsafe { magic_error(self.cookie) };
        (!error.is_null()).then(|| unsafe { CStr::from_ptr(error) }.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_isnt_a_database_in_this_byte_order_is_refused() {
        let dir = tempfile::tempdir().expect("a directory");
        let mut swapped = std::fs::read(DATABASE).expect("the database reads");
        swapped[..4].reverse();
        for (name, bytes) in [
            ("empty", &[][..]),
            ("text", b"not a database"),
            ("swapped", &swapped),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).expect("written");
            let error = Database::open(&path).err().expect("refused");
            assert!(
                error.contains("not a compiled libmagic database"),
                "{name}: {error}"
            );
            let error = Cookie::load(bytes, MAGIC_NONE).err().expect("refused");
            assert!(
                error.contains("not a compiled libmagic database"),
                "{name}: {error}"
            );
        }
        let missing = Database::open(&dir.path().join("missing"))
            .err()
            .expect("refused");
        assert!(missing.contains("missing"), "{missing}");
    }

    /// A cookie over the mapping and one over a copy of the bytes answer alike.
    #[test]
    fn a_cookie_over_the_mapping_answers_as_one_over_a_copy() {
        let database = Database::open(Path::new(DATABASE)).expect("the database maps");
        let copy = std::fs::read(DATABASE).expect("the database reads");
        let blob = b"<html><body><a href=\"https://a.example.com/\">a</a></body></html>\n";
        let mapped = Cookie::load(database.bytes(), MAGIC_NONE).expect("libmagic");
        let copied = Cookie::load(&copy, MAGIC_NONE).expect("libmagic");
        let answer = mapped.buffer(blob).expect("an answer");
        assert_eq!(answer, copied.buffer(blob).expect("an answer"));
        assert!(answer.starts_with(b"HTML document"), "{answer:?}");
    }
}
