//! A file's mime type from libmagic, for the `mime_type` filter directive.
//!
//! ace3 runs `file -b --mime-type` on the file for each scan that needs it. Here libmagic,
//! the library `file` is built on, reads the bytes, and the magic database is a fixed file
//! pinned in the image (`docker/dev/Dockerfile`), so the answers don't change under the
//! rules. The pinned database is the one ace3's image has.
//!
//! libmagic is given the bytes as a file, not a buffer. Some magic reads at an offset from
//! the end of the file, zip's end-of-central-directory record among it, and libmagic reads
//! those only through a file descriptor: `magic_buffer` on a zip's bytes answers
//! `application/octet-stream`, as `file` does for a zip on a pipe, where `file` on the path
//! answers `application/zip`. So the bytes go into an in-memory file, and libmagic opens it by
//! path, as `file` does.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use magic::cookie::{DatabasePaths, Flags, Load};
use rustix::fs::{MemfdFlags, memfd_create};

/// Where the dev image keeps the pinned magic database.
pub const DEFAULT_DATABASE: &str = "/usr/lib/file/magic.mgc";

/// libmagic with one database loaded. A libmagic cookie isn't safe to share between threads,
/// so each thread opens its own.
pub struct MimeTyper {
    cookie: magic::Cookie<Load>,
    database: PathBuf,
}

#[derive(Debug)]
pub struct MimeError(String);

impl fmt::Display for MimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MimeError {}

impl MimeTyper {
    /// Opens libmagic with only the given database, so nothing in `/etc/magic` or `MAGIC`
    /// changes the answers.
    pub fn open(database: &Path) -> Result<Self, MimeError> {
        // SYMLINK, because the in-memory file is opened through the /proc/self/fd link.
        let cookie = magic::Cookie::open(Flags::MIME_TYPE | Flags::SYMLINK)
            .map_err(|e| MimeError(format!("unable to open libmagic: {e}")))?;
        let paths = DatabasePaths::new([database]).map_err(|e| {
            MimeError(format!(
                "invalid magic database path {}: {e}",
                database.display()
            ))
        })?;
        let cookie = cookie.load(&paths).map_err(|e| {
            MimeError(format!(
                "unable to load magic database {}: {e}",
                database.display()
            ))
        })?;
        Ok(MimeTyper {
            cookie,
            database: database.to_path_buf(),
        })
    }

    pub fn database(&self) -> &Path {
        &self.database
    }

    /// The mime type of the bytes, as `file -b --mime-type` gives it for a file holding them.
    pub fn mime_type(&self, data: &[u8]) -> Result<String, MimeError> {
        let file = in_memory_file(data)
            .map_err(|e| MimeError(format!("unable to hold the bytes in memory: {e}")))?;
        self.mime_type_of_path(Path::new(&format!("/proc/self/fd/{}", file.as_raw_fd())))
    }

    /// The mime type of the file at `path`, as `file -b --mime-type` gives it, for a file that
    /// is already on disk, such as one the bucket spooled. libmagic reads only the parts of it
    /// the magic asks for.
    pub fn mime_type_of_path(&self, path: &Path) -> Result<String, MimeError> {
        self.cookie
            .file(path)
            .map_err(|e| MimeError(format!("libmagic failed: {e}")))
    }
}

/// A file in memory holding `data`, closed when dropped. Opening it again through
/// `/proc/self/fd` starts at its beginning.
fn in_memory_file(data: &[u8]) -> std::io::Result<File> {
    let mut file = File::from(memfd_create("ace-yara-mime", MemfdFlags::CLOEXEC)?);
    file.write_all(data)?;
    Ok(file)
}
