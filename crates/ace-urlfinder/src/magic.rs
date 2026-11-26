//! `magic.from_buffer(blob)` of python-magic 0.4.27: libmagic's description of the bytes, with
//! no flags and the name/use limit raised to 64, as its `Magic()` sets it.
//!
//! A contained task can't open the database, so a module maps it before containment
//! (`Database::open`), and a task that needs libmagic makes a cookie over that mapping, without a
//! copy (`ace_libmagic`). libmagic is the one ace3's image has, 5.46, and the database is the same
//! file (`docker/ace-rs/Dockerfile` pins both).

use std::path::Path;

use ace_libmagic::{Cookie, MAGIC_NONE, MAGIC_PARAM_NAME_MAX};
use ace_pycompat::PyErr;

/// Where ace-rs's images keep the database, the one ace3's python-magic loads by default.
pub use ace_libmagic::DATABASE;

/// libmagic's database, mapped before containment, for the tasks that load libmagic: most give
/// urlfinderlib a description of their bytes, and never do.
pub struct Database {
    database: Result<ace_libmagic::Database, String>,
}

impl Database {
    /// The database at `path`; a module's `init` passes [`DATABASE`]. A database that won't map
    /// is an error only for a task that loads libmagic.
    pub fn open(path: &Path) -> Database {
        Database {
            database: ace_libmagic::Database::open(path),
        }
    }

    /// libmagic over the mapping.
    pub fn load(&self) -> Result<Magic<'_>, String> {
        let database = self.database.as_ref().map_err(Clone::clone)?;
        Magic::load(database.bytes())
    }
}

/// libmagic with a database loaded, as python-magic's `Magic()` sets it up. Not shared between
/// threads.
pub struct Magic<'d> {
    cookie: Cookie<'d>,
}

impl<'d> Magic<'d> {
    /// A cookie over a compiled database's bytes, which it borrows.
    pub fn load(database: &'d [u8]) -> Result<Magic<'d>, String> {
        let cookie = Cookie::load(database, MAGIC_NONE)?;
        // python-magic ignores a failure here
        cookie.set_param(MAGIC_PARAM_NAME_MAX, 64);
        Ok(Magic { cookie })
    }

    /// `magic.from_buffer(blob)`: the description, decoded as UTF-8 with backslashreplace; a
    /// libmagic error is python-magic's MagicException.
    pub fn from_buffer(&self, blob: &[u8]) -> Result<String, PyErr> {
        match self.cookie.buffer(blob) {
            Ok(answer) => Ok(backslashreplace(&answer)),
            Err(error) => {
                let message = error.map_or_else(|| "None".to_owned(), |e| backslashreplace(&e));
                Err(PyErr::new("magic", "MagicException", message))
            }
        }
    }
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
