//! libmagic, as ace3's `file -b -L` and `file -b --mime-type -L` run it.
//!
//! The database is mapped read-only before containment, which can't open it, and each cookie
//! loads from that mapping in the task, without a copy (`ace_libmagic`). libmagic and the database
//! are the ones ace3's image has, 5.46 (the dev image and `docker/ace-rs/Dockerfile` pin both).
//! `file` opens the file by its path, and so does `magic_file` here: by a descriptor or a buffer
//! libmagic answers some files differently, an empty file's mime type among them.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use ace_libmagic::{Cookie, MAGIC_MIME_TYPE, MAGIC_SYMLINK};

pub use ace_libmagic::{DATABASE, Database};

/// What `file` prints: the description, or its mime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Description,
    MimeType,
}

impl Answer {
    /// `-L`, and `--mime-type` for the mime type.
    fn flags(self) -> std::ffi::c_int {
        match self {
            Answer::Description => MAGIC_SYMLINK,
            Answer::MimeType => MAGIC_SYMLINK | MAGIC_MIME_TYPE,
        }
    }
}

/// libmagic with a database loaded. Not shared between threads.
pub struct Magic<'d> {
    cookie: Cookie<'d>,
}

impl<'d> Magic<'d> {
    /// A cookie over the database, which it borrows rather than copies.
    pub fn load(database: &'d Database, answer: Answer) -> Result<Magic<'d>, String> {
        Ok(Magic {
            cookie: Cookie::load(database.bytes(), answer.flags())?,
        })
    }

    /// What `file -b` prints for the file, without its newline: libmagic's answer, or `ERROR: `
    /// and libmagic's error when it has none.
    pub fn file(&self, path: &Path) -> String {
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return "ERROR: the path holds a NUL".to_owned();
        };
        match self.cookie.file(&path) {
            Ok(answer) => String::from_utf8_lossy(&answer).into_owned(),
            Err(error) => format!(
                "ERROR: {}",
                String::from_utf8_lossy(&error.unwrap_or_default())
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let copy: Box<[u8]> = std::fs::read(DATABASE).expect("the database reads").into();
        let database = Database::open(Path::new(DATABASE)).expect("the database maps");
        for answer_kind in [Answer::Description, Answer::MimeType] {
            let mapped = Magic::load(&database, answer_kind).expect("libmagic");
            let copied = Magic {
                cookie: Cookie::load(&copy, answer_kind.flags()).expect("libmagic"),
            };
            for path in &files {
                assert_eq!(
                    mapped.file(path),
                    copied.file(path),
                    "{answer_kind:?} of {}",
                    path.display()
                );
            }
        }
    }
}
