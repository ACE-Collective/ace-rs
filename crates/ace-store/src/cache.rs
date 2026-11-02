//! Each node's cache of the bucket: a directory capped at a size, evicted oldest first.
//!
//! As in ace3's CAS read cache, an entry's mtime is when it was last read, and eviction removes
//! the oldest entries until the cache fits. Walking the directory to add up its size costs as
//! much as many reads, so a process walks it on its first fill and then after filling another
//! 1% of the cap, and the cache can run over by about that much between walks. Readers get an
//! open file: another process may evict the entry at any moment, and an open file outlives
//! that.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;

use ace_results::Sha256;
use tempfile::NamedTempFile;

/// The directory temporary files are spooled to, inside the cache's own directory so a finished
/// one can be renamed into place.
const TEMP_DIR: &str = ".tmp";

/// A node's cache directory and its size cap.
#[derive(Debug, Clone)]
pub struct NodeCache {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    dir: PathBuf,
    max_bytes: u64,
    walked: AtomicBool,
    filled_since_walk: AtomicU64,
}

/// An object's bytes on this node.
#[derive(Debug)]
pub struct CachedFile {
    /// The bytes, open. Read through this rather than the path, which eviction can remove.
    pub file: File,
    pub path: PathBuf,
    pub size: u64,
    /// True when the node already had the bytes and the bucket wasn't asked.
    pub from_cache: bool,
}

/// What a walk of the cache found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: u64,
    pub bytes: u64,
    pub evicted: u64,
}

impl NodeCache {
    /// A cache in `dir`, created if missing, holding at most about `max_bytes`.
    pub fn new(dir: impl Into<PathBuf>, max_bytes: u64) -> io::Result<NodeCache> {
        let dir = dir.into();
        fs::create_dir_all(dir.join(TEMP_DIR))?;
        Ok(NodeCache {
            inner: Arc::new(Inner {
                dir,
                max_bytes,
                walked: AtomicBool::new(false),
                filled_since_walk: AtomicU64::new(0),
            }),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }

    pub fn max_bytes(&self) -> u64 {
        self.inner.max_bytes
    }

    /// Where the object's bytes are kept: `<dir>/<pool>/<sha[0..2]>/<sha>`.
    pub fn path_of(&self, pool: &str, sha256: &Sha256) -> PathBuf {
        let hex = sha256.to_hex();
        self.inner.dir.join(pool).join(&hex[..2]).join(hex)
    }

    pub(crate) fn temp_file(&self) -> io::Result<NamedTempFile> {
        NamedTempFile::new_in(self.inner.dir.join(TEMP_DIR))
    }

    /// Opens a cached object and marks it as just read. None when the node doesn't have it.
    pub fn open(&self, pool: &str, sha256: &Sha256) -> io::Result<Option<CachedFile>> {
        let path = self.path_of(pool, sha256);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        // the entry's mtime is when it was last read; failing to bump it only makes it older
        if let Err(e) = file.set_modified(SystemTime::now()) {
            tracing::debug!(path = %path.display(), "couldn't mark a cache entry as read: {e}");
        }
        let size = file.metadata()?.len();
        Ok(Some(CachedFile {
            file,
            path,
            size,
            from_cache: true,
        }))
    }

    /// Moves a finished temporary file into the cache and opens it. With a cap of 0 the cache
    /// is off: the file is opened and its path removed.
    pub(crate) fn insert(
        &self,
        pool: &str,
        sha256: &Sha256,
        temp: NamedTempFile,
    ) -> io::Result<CachedFile> {
        let size = temp.as_file().metadata()?.len();
        let path = self.path_of(pool, sha256);
        if self.inner.max_bytes == 0 {
            let file = temp.reopen()?;
            return Ok(CachedFile {
                file,
                path: temp.path().to_path_buf(),
                size,
                from_cache: false,
            });
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        temp.persist(&path).map_err(|e| e.error)?;
        let file = File::open(&path)?;
        let filled = self
            .inner
            .filled_since_walk
            .fetch_add(size, Ordering::Relaxed)
            + size;
        let first = !self.inner.walked.swap(true, Ordering::Relaxed);
        if first || filled >= self.inner.max_bytes / 100 {
            self.inner.filled_since_walk.store(0, Ordering::Relaxed);
            self.evict()?;
        }
        Ok(CachedFile {
            file,
            path,
            size,
            from_cache: false,
        })
    }

    /// Removes an object from the cache, if it is there.
    pub fn remove(&self, pool: &str, sha256: &Sha256) -> io::Result<()> {
        match fs::remove_file(self.path_of(pool, sha256)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Walks the cache and removes the least recently read entries until it fits its cap.
    pub fn evict(&self) -> io::Result<CacheStats> {
        let mut entries = Vec::new();
        walk(&self.inner.dir, &mut entries)?;
        let mut stats = CacheStats {
            entries: entries.len() as u64,
            bytes: entries.iter().map(|e| e.size).sum(),
            evicted: 0,
        };
        if stats.bytes <= self.inner.max_bytes {
            return Ok(stats);
        }
        entries.sort_by_key(|e| e.modified);
        for entry in entries {
            if stats.bytes <= self.inner.max_bytes {
                break;
            }
            // an entry read since the walk is kept
            let modified = fs::metadata(&entry.path).and_then(|m| m.modified()).ok();
            if modified != Some(entry.modified) {
                continue;
            }
            match fs::remove_file(&entry.path) {
                Ok(()) => {
                    stats.bytes -= entry.size;
                    stats.entries -= 1;
                    stats.evicted += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(stats)
    }
}

struct Entry {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

fn walk(dir: &Path, entries: &mut Vec<Entry>) -> io::Result<()> {
    for item in fs::read_dir(dir)? {
        let item = item?;
        if item.file_name() == TEMP_DIR {
            continue;
        }
        let metadata = item.metadata()?;
        if metadata.is_dir() {
            walk(&item.path(), entries)?;
        } else {
            entries.push(Entry {
                path: item.path(),
                size: metadata.len(),
                modified: metadata.modified()?,
            });
        }
    }
    Ok(())
}
