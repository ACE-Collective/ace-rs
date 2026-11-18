//! Writing the files a module produces.
//!
//! A module hands the SDK a file's bytes, its path inside the alert and its role, what the module
//! made it (`FileRole`), from which its `yara_meta` tag `type=<role>` is built. The
//! bytes go into a file store under their sha256, and the module gets back the `NewFile` record
//! to put in its result. Names often come from inside hostile files, so the path is checked
//! first: an absolute path or a `..` part fails and nothing is stored (ace3 #829).
//!
//! The store is a local directory until the bucket replaces it (PLAN.md 2.5).

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ace_results::{AlertPath, FileRole, InvalidAlertPath, NewFile, Sha256};
use sha2::Digest;

/// Where a module's output files go: bytes stored by their sha256.
pub trait FileStore: Send + Sync {
    /// Stores everything `bytes` yields and returns its sha256 and size. Storing the same bytes
    /// twice keeps one copy.
    fn put(&self, bytes: &mut dyn Read) -> io::Result<(Sha256, u64)>;

    /// Opens the bytes stored under `sha256`.
    fn open(&self, sha256: &Sha256) -> io::Result<Box<dyn Read + Send>>;
}

/// A file store in a local directory: one file per sha256, named by its hex.
#[derive(Debug, Clone)]
pub struct LocalFileStore {
    dir: PathBuf,
}

impl LocalFileStore {
    /// A store in `dir`, which is created if it is missing.
    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(LocalFileStore { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the bytes stored under `sha256` are.
    pub fn path_of(&self, sha256: &Sha256) -> PathBuf {
        self.dir.join(sha256.to_hex())
    }
}

impl FileStore for LocalFileStore {
    fn put(&self, bytes: &mut dyn Read) -> io::Result<(Sha256, u64)> {
        // hash while copying into a temporary file in the same directory, then rename it
        let mut temp = tempfile::NamedTempFile::new_in(&self.dir)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let read = match bytes.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            hasher.update(&buffer[..read]);
            temp.write_all(&buffer[..read])?;
            size += read as u64;
        }
        temp.as_file().sync_all()?;
        let sha256 = Sha256(hasher.finalize().into());
        let path = self.path_of(&sha256);
        if path.exists() {
            // the same bytes are already stored; the temporary file is removed on drop
            return Ok((sha256, size));
        }
        temp.persist(&path).map_err(|e| e.error)?;
        Ok((sha256, size))
    }

    fn open(&self, sha256: &Sha256) -> io::Result<Box<dyn Read + Send>> {
        Ok(Box::new(fs::File::open(self.path_of(sha256))?))
    }
}

/// A file that couldn't be written.
#[derive(Debug, thiserror::Error)]
pub enum FileOutputError {
    #[error(transparent)]
    InvalidPath(#[from] InvalidAlertPath),
    #[error("the task has no file store")]
    NoStore,
    #[error("couldn't store {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// Checks `path`, stores the bytes `reader` yields, and returns the file's record, with `role` and
/// the `type=` tag built from it.
pub fn write_file(
    store: &dyn FileStore,
    path: &str,
    reader: &mut dyn Read,
    role: Option<FileRole>,
) -> Result<NewFile, FileOutputError> {
    let path = AlertPath::new(path)?;
    let (sha256, size) = store.put(reader).map_err(|source| FileOutputError::Io {
        path: path.to_string(),
        source,
    })?;
    let mut file = NewFile::new(path, sha256, size);
    if let Some(role) = role {
        file.set_role(role);
    }
    Ok(file)
}
