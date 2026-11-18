//! Bytes on their way into the bucket: in a temporary file on this node, with their sha256 and
//! size.

use std::path::PathBuf;

use ace_results::Sha256;
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
        Ok(Spooled {
            temp,
            sha256: Sha256(hasher.finalize().into()),
            size,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.temp.path().to_path_buf()
    }

    pub(crate) fn into_temp(self) -> NamedTempFile {
        self.temp
    }
}
