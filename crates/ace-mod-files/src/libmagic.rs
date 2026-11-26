//! libmagic, as ace3's `file -b -L` and `file -b --mime-type -L` run it.
//!
//! The database is mapped read-only before containment, which can't open it (`Database::open`), and
//! each cookie loads from that mapping in the task, without a copy: libmagic keeps pointers into
//! the bytes it loads, and reads only the pages it matches against, so a task reads few of its
//! 10 MB. Landlock checks a file only when it is opened, so the mapping still reads once the task
//! is contained. libmagic and the database are the ones ace3's image has, 5.46 (the dev image
//! and `docker/ace-rs/Dockerfile` pin both). `file` opens the file by its path, and so does
//! `magic_file` here: by a descriptor or a buffer libmagic answers some files differently, an empty
//! file's mime type among them.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::File;
use std::marker::PhantomData;
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

/// The first word of a compiled database, file.h's `MAGICNO`, in the order libmagic reads it.
const MAGICNO: u32 = 0xF11E_041C;

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
        // libmagic swaps a database of the other byte order in place, which would write to a
        // read-only mapping; one in this machine's order it only reads (apprentice.c's
        // check_buffer)
        let first = map
            .get(..4)
            .map(|word| u32::from_ne_bytes(word.try_into().expect("four bytes")));
        if first != Some(MAGICNO) {
            return Err(format!(
                "{}: not a compiled libmagic database in this machine's byte order",
                path.display()
            ));
        }
        Ok(Database { map })
    }
}

/// What `file` prints: the description, or its mime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Description,
    MimeType,
}

/// libmagic with a database loaded. Not shared between threads.
pub struct Magic<'d> {
    cookie: magic_t,
    // libmagic keeps pointers into the database it loaded
    _database: PhantomData<&'d Database>,
}

impl Drop for Magic<'_> {
    fn drop(&mut self) {
        unsafe { magic_close(self.cookie) };
    }
}

impl<'d> Magic<'d> {
    /// A cookie over the database, which it borrows rather than copies.
    pub fn load(database: &'d Database, answer: Answer) -> Result<Magic<'d>, String> {
        let flags = match answer {
            Answer::Description => MAGIC_SYMLINK,
            Answer::MimeType => MAGIC_SYMLINK | MAGIC_MIME_TYPE,
        };
        unsafe {
            let cookie = magic_open(flags);
            if cookie.is_null() {
                return Err("magic_open failed".to_owned());
            }
            // magic.h's signature takes mutable buffers, but libmagic writes to one only to swap
            // its byte order, which `Database::open` refused
            let mut buffers = [database.map.as_ptr() as *mut c_void];
            let mut sizes = [database.map.len()];
            if magic_load_buffers(cookie, buffers.as_mut_ptr(), sizes.as_mut_ptr(), 1) != 0 {
                let error = error_text(cookie);
                magic_close(cookie);
                return Err(format!("magic_load_buffers failed: {error}"));
            }
            Ok(Magic {
                cookie,
                _database: PhantomData,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A cookie made as `Magic::load` made one before the database was mapped: over a copy of
    /// its bytes, owned by the cookie.
    struct Copied {
        cookie: magic_t,
        _database: Box<[u8]>,
    }

    impl Drop for Copied {
        fn drop(&mut self) {
            unsafe { magic_close(self.cookie) };
        }
    }

    fn copied(bytes: &[u8], answer: Answer) -> Copied {
        let flags = match answer {
            Answer::Description => MAGIC_SYMLINK,
            Answer::MimeType => MAGIC_SYMLINK | MAGIC_MIME_TYPE,
        };
        let mut database: Box<[u8]> = bytes.into();
        unsafe {
            let cookie = magic_open(flags);
            assert!(!cookie.is_null());
            let mut buffers = [database.as_mut_ptr() as *mut c_void];
            let mut sizes = [database.len()];
            assert_eq!(
                magic_load_buffers(cookie, buffers.as_mut_ptr(), sizes.as_mut_ptr(), 1),
                0
            );
            Copied {
                cookie,
                _database: database,
            }
        }
    }

    /// The same cookie as a `Magic`, to ask it the same way.
    fn answer(cookie: &Copied, path: &Path) -> String {
        let magic = Magic {
            cookie: cookie.cookie,
            _database: PhantomData,
        };
        let answer = magic.file(path);
        // the cookie is `cookie`'s to close
        std::mem::forget(magic);
        answer
    }

    fn files_under(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("the directory reads") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                files_under(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    /// Cookies over the one mapping answer as cookies over their own copies did, both answers, on
    /// every committed sample and fixture.
    #[test]
    fn the_mapped_database_answers_as_a_copy_of_it_did() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        for dir in [
            "samples/ace3",
            "samples/ace-rs",
            "tools/ace3/dumps/fixtures",
        ] {
            files_under(&root.join(dir), &mut files);
        }
        assert!(files.len() > 800, "only {} files", files.len());
        let bytes = std::fs::read(DATABASE).expect("the database reads");
        let database = Database::open(Path::new(DATABASE)).expect("the database maps");
        for answer_kind in [Answer::Description, Answer::MimeType] {
            let mapped = Magic::load(&database, answer_kind).expect("libmagic");
            let copy = copied(&bytes, answer_kind);
            for path in &files {
                assert_eq!(
                    mapped.file(path),
                    answer(&copy, path),
                    "{answer_kind:?} of {}",
                    path.display()
                );
            }
        }
    }

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
        }
        let missing = Database::open(&dir.path().join("missing"))
            .err()
            .expect("refused");
        assert!(missing.contains("missing"), "{missing}");
    }
}
