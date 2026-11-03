//! The content-addressed bucket (PLAN.md 2.5): bytes stored by their sha256 in an S3 bucket,
//! in named pools, with a size-capped cache of them on each node.
//!
//! This is ace3's CAS (`docs/CAS.md`) grown into the only file store. An object's key is
//! `<pool>/<sha[0..2]>/<sha[2..4]>/<sha>`, and dedup happens within a pool. This crate moves
//! bytes. Which objects exist, what holds them and when one may be deleted is the index in
//! ace-core's `store` schema, which never lists the bucket to find out.
//!
//! A put spools the bytes to a temporary file on the node while hashing them, asks libmagic
//! for their mime type (`ace_yara::mime`, the pinned database), and uploads them with that type
//! unless the bucket already has them. The spooled file then joins the node's cache. A get
//! reads the node's cache first and fills it from the bucket otherwise, checking the bytes'
//! sha256 before they reach the cache.

mod cache;
mod config;
mod spool;

use std::path::Path;

use ace_results::Sha256;
use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
use aws_sdk_s3::error::DisplayErrorContext;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use sha2::Digest;
use tokio::io::AsyncWriteExt;

pub use cache::{CacheStats, CachedFile, NodeCache};
pub use config::BucketConfig;
pub use spool::Spooled;

/// The key prefix of files a worker uploads before the core checks them (`Store::upload_key`).
/// It isn't a pool: a file reaches its pool only after its bytes match its name.
pub const UPLOADS: &str = "uploads";

/// A request the bucket accepts without credentials until it expires: a URL, and headers the
/// signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presigned {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// The node cache's default cap, ace3's `cas.read_cache.max_bytes`: 10 GiB.
pub const DEFAULT_CACHE_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0} isn't set")]
    MissingConfig(&'static str),
    #[error("invalid pool name {0:?}: use lowercase letters, digits, - and _")]
    InvalidPool(String),
    #[error("{key} isn't in the bucket")]
    NotFound { key: String },
    #[error("{key} holds bytes whose sha256 is {actual}")]
    Integrity { key: String, actual: Sha256 },
    #[error("bucket {operation} of {key}: {message}")]
    Bucket {
        operation: &'static str,
        key: String,
        message: String,
    },
    #[error("mime type: {0}")]
    Mime(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The bucket and this node's cache of it.
#[derive(Debug, Clone)]
pub struct Store {
    s3: aws_sdk_s3::Client,
    bucket: String,
    cache: NodeCache,
}

impl Store {
    pub fn new(config: &BucketConfig, cache: NodeCache) -> Store {
        let mut s3 = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .credentials_provider(Credentials::new(
                &config.access_key,
                config.secret_key.expose(),
                None,
                None,
                "ace4",
            ))
            .force_path_style(config.path_style)
            // Checksums only where S3 requires them: not every S3-compatible server takes the
            // SDK's default CRC32 trailers, and gets are checked against the sha256 anyway.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired);
        if let Some(endpoint) = &config.endpoint {
            s3 = s3.endpoint_url(endpoint);
        }
        Store {
            s3: aws_sdk_s3::Client::from_conf(s3.build()),
            bucket: config.bucket.clone(),
            cache,
        }
    }

    pub fn cache(&self) -> &NodeCache {
        &self.cache
    }

    /// The object's key in the bucket.
    pub fn key(pool: &str, sha256: &Sha256) -> Result<String, StoreError> {
        check_pool(pool)?;
        let hex = sha256.to_hex();
        Ok(format!("{pool}/{}/{}/{hex}", &hex[..2], &hex[2..4]))
    }

    /// Where a worker uploads a file its task wrote: `uploads/<task>/<sha256>`, a key of the
    /// task's own, so a worker can't put bytes under a pool's name for them.
    pub fn upload_key(task: i64, sha256: &Sha256) -> String {
        format!("{UPLOADS}/{task}/{}", sha256.to_hex())
    }

    /// A URL that downloads the object until `expires`.
    pub async fn presign_get(
        &self,
        pool: &str,
        sha256: &Sha256,
        expires: std::time::Duration,
    ) -> Result<Presigned, StoreError> {
        let key = Store::key(pool, sha256)?;
        let request = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .presigned(presigning(expires, &key)?)
            .await
            .map_err(|e| bucket_error("presign get", key.clone(), e))?;
        Ok(presigned(&request))
    }

    /// A URL that uploads `size` bytes to `key` until `expires`.
    pub async fn presign_put(
        &self,
        key: &str,
        size: u64,
        expires: std::time::Duration,
    ) -> Result<Presigned, StoreError> {
        let request = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(i64::try_from(size).unwrap_or(i64::MAX))
            .presigned(presigning(expires, key)?)
            .await
            .map_err(|e| bucket_error("presign put", key.to_owned(), e))?;
        Ok(presigned(&request))
    }

    /// Downloads `key` and spools it on this node, failing unless its sha256 is `expected`,
    /// as when the core checks a file a worker uploaded.
    pub async fn spool_key(&self, key: &str, expected: &Sha256) -> Result<Spooled, StoreError> {
        let response = match self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) if e.as_service_error().is_some_and(|e| e.is_no_such_key()) => {
                return Err(StoreError::NotFound {
                    key: key.to_owned(),
                });
            }
            Err(e) => return Err(bucket_error("get", key.to_owned(), e)),
        };
        let mut reader = response.body.into_async_read();
        let spooled = Spooled::from_reader(&self.cache, &mut reader).await?;
        if spooled.sha256 != *expected {
            return Err(StoreError::Integrity {
                key: key.to_owned(),
                actual: spooled.sha256,
            });
        }
        Ok(spooled)
    }

    /// Deletes `key`, which isn't an object of a pool, such as an upload. A missing key is not
    /// an error.
    pub async fn delete_key(&self, key: &str) -> Result<(), StoreError> {
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| bucket_error("delete", key.to_owned(), e))?;
        Ok(())
    }

    /// Spools `bytes` on this node, with their sha256, size and mime type.
    pub async fn spool_bytes(&self, bytes: &[u8]) -> Result<Spooled, StoreError> {
        Spooled::from_reader(&self.cache, &mut &bytes[..]).await
    }

    /// Spools a copy of the file at `path`.
    pub async fn spool_file(&self, path: &Path) -> Result<Spooled, StoreError> {
        let mut file = tokio::fs::File::open(path).await?;
        Spooled::from_reader(&self.cache, &mut file).await
    }

    /// True when the bucket has the object.
    pub async fn exists(&self, pool: &str, sha256: &Sha256) -> Result<bool, StoreError> {
        let key = Store::key(pool, sha256)?;
        match self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.as_service_error().is_some_and(|e| e.is_not_found()) => Ok(false),
            Err(e) => Err(bucket_error("head", key, e)),
        }
    }

    /// Uploads spooled bytes to `pool`, with their mime type as the object's content type.
    /// Uploading bytes the bucket already has rewrites the same object.
    pub async fn upload(&self, pool: &str, spooled: &Spooled) -> Result<(), StoreError> {
        let key = Store::key(pool, &spooled.sha256)?;
        let body = ByteStream::from_path(spooled.path())
            .await
            .map_err(|e| bucket_error("read for upload", key.clone(), e))?;
        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type(&spooled.mime_type)
            .content_length(i64::try_from(spooled.size).unwrap_or(i64::MAX))
            .body(body)
            .send()
            .await
            .map_err(|e| bucket_error("put", key, e))?;
        Ok(())
    }

    /// Moves spooled bytes into this node's cache, since the node already has them.
    pub async fn keep(&self, pool: &str, spooled: Spooled) -> Result<CachedFile, StoreError> {
        check_pool(pool)?;
        let sha256 = spooled.sha256;
        self.insert(pool, sha256, spooled.into_temp()).await
    }

    /// Moves a finished temporary file into the cache on a blocking thread, since the cache may
    /// walk its directory to evict.
    async fn insert(
        &self,
        pool: &str,
        sha256: Sha256,
        temp: tempfile::NamedTempFile,
    ) -> Result<CachedFile, StoreError> {
        let cache = self.cache.clone();
        let pool = pool.to_owned();
        let inserted = tokio::task::spawn_blocking(move || cache.insert(&pool, &sha256, temp))
            .await
            .map_err(|e| std::io::Error::other(format!("the cache's thread failed: {e}")))?;
        Ok(inserted?)
    }

    /// The object's bytes, from this node's cache, or from the bucket into the cache.
    pub async fn get(&self, pool: &str, sha256: &Sha256) -> Result<CachedFile, StoreError> {
        let key = Store::key(pool, sha256)?;
        if let Some(file) = self.cache.open(pool, sha256)? {
            return Ok(file);
        }
        let response = match self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) if e.as_service_error().is_some_and(|e| e.is_no_such_key()) => {
                return Err(StoreError::NotFound { key });
            }
            Err(e) => return Err(bucket_error("get", key, e)),
        };
        let temp = self.cache.temp_file()?;
        let mut out = tokio::fs::File::from_std(temp.reopen()?);
        let mut hasher = sha2::Sha256::new();
        let mut body = response.body;
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|e| bucket_error("read", key.clone(), e))?
        {
            hasher.update(&chunk);
            out.write_all(&chunk).await?;
        }
        out.flush().await?;
        out.sync_all().await?;
        drop(out);
        let actual = Sha256(hasher.finalize().into());
        if actual != *sha256 {
            return Err(StoreError::Integrity { key, actual });
        }
        self.insert(pool, actual, temp).await
    }

    /// Deletes the object from the bucket and from this node's cache. Deleting one that isn't
    /// there is not an error.
    pub async fn delete(&self, pool: &str, sha256: &Sha256) -> Result<(), StoreError> {
        let key = Store::key(pool, sha256)?;
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| bucket_error("delete", key, e))?;
        self.cache.remove(pool, sha256)?;
        Ok(())
    }

    /// The keys in the bucket that start with `prefix`. Only maintenance and tests list the
    /// bucket; the index decides what exists.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut keys = Vec::new();
        let mut pages = self
            .s3
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page.map_err(|e| bucket_error("list", prefix.to_owned(), e))?;
            keys.extend(
                page.contents()
                    .iter()
                    .filter_map(|object| object.key().map(str::to_owned)),
            );
        }
        Ok(keys)
    }
}

fn presigning(expires: std::time::Duration, key: &str) -> Result<PresigningConfig, StoreError> {
    PresigningConfig::expires_in(expires).map_err(|e| StoreError::Bucket {
        operation: "presign",
        key: key.to_owned(),
        message: e.to_string(),
    })
}

fn presigned(request: &aws_sdk_s3::presigning::PresignedRequest) -> Presigned {
    Presigned {
        url: request.uri().to_owned(),
        headers: request
            .headers()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
    }
}

fn check_pool(pool: &str) -> Result<(), StoreError> {
    let valid = !pool.is_empty()
        && pool
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidPool(pool.to_owned()))
    }
}

fn bucket_error(operation: &'static str, key: String, error: impl std::error::Error) -> StoreError {
    StoreError::Bucket {
        operation,
        key,
        message: DisplayErrorContext(error).to_string(),
    }
}
