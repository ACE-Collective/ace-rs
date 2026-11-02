//! Bytes on their way into the bucket: in a temporary file on this node, with their sha256,
//! size and mime type.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use ace_results::Sha256;
use ace_yara::mime::{DEFAULT_DATABASE, MimeTyper};
use sha2::Digest;
use tempfile::NamedTempFile;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::StoreError;
use crate::cache::NodeCache;

/// Bytes spooled to a temporary file in the node cache's directory. Dropping it removes the
/// file; `Store::keep` moves it into the cache instead.
#[derive(Debug)]
pub struct Spooled {
    temp: NamedTempFile,
    pub sha256: Sha256,
    pub size: u64,
    /// libmagic's answer for the bytes, from the pinned magic database.
    pub mime_type: String,
}

impl Spooled {
    pub(crate) async fn from_reader(
        cache: &NodeCache,
        reader: &mut (dyn AsyncRead + Unpin + Send),
    ) -> Result<Spooled, StoreError> {
        let temp = cache.temp_file()?;
        let mut out = tokio::fs::File::from_std(temp.reopen()?);
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; 256 * 1024];
        let mut size = 0u64;
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            out.write_all(&buffer[..read]).await?;
            size += read as u64;
        }
        out.flush().await?;
        out.sync_all().await?;
        drop(out);
        let path = temp.path().to_path_buf();
        let mime_type = tokio::task::spawn_blocking(move || mime_type_of(&path))
            .await
            .map_err(|e| StoreError::Mime(format!("the mime type's thread failed: {e}")))??;
        Ok(Spooled {
            temp,
            sha256: Sha256(hasher.finalize().into()),
            size,
            mime_type,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.temp.path().to_path_buf()
    }

    pub(crate) fn into_temp(self) -> NamedTempFile {
        self.temp
    }
}

thread_local! {
    /// A libmagic cookie can't be shared between threads, so each blocking thread opens its own
    /// the first time it types a file.
    static TYPER: RefCell<Option<MimeTyper>> = const { RefCell::new(None) };
}

fn mime_type_of(path: &Path) -> Result<String, StoreError> {
    TYPER.with(|cell| {
        let mut typer = cell.borrow_mut();
        if typer.is_none() {
            let opened = MimeTyper::open(Path::new(DEFAULT_DATABASE))
                .map_err(|e| StoreError::Mime(e.to_string()))?;
            *typer = Some(opened);
        }
        match typer.as_ref() {
            Some(typer) => typer
                .mime_type_of_path(path)
                .map_err(|e| StoreError::Mime(e.to_string())),
            None => Err(StoreError::Mime("libmagic didn't open".to_owned())),
        }
    })
}
