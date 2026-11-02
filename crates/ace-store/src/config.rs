//! Where the bucket is and how to reach it.

use std::fmt;

use crate::StoreError;

/// The bucket's endpoint, name and credentials.
#[derive(Debug, Clone)]
pub struct BucketConfig {
    /// An S3-compatible server's URL, such as `http://bucket:8333`. None means AWS S3 itself.
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: SecretKey,
    /// Path-style URLs (`endpoint/bucket/key`), which S3-compatible servers want, rather than
    /// a host name per bucket.
    pub path_style: bool,
}

impl BucketConfig {
    /// `ACE4_BUCKET_ENDPOINT`, `ACE4_BUCKET_REGION` (default `us-east-1`), `ACE4_BUCKET_NAME`,
    /// `ACE4_BUCKET_ACCESS_KEY` and `ACE4_BUCKET_SECRET_KEY`. With an endpoint, URLs are
    /// path-style.
    pub fn from_env() -> Result<Self, StoreError> {
        let var =
            |name: &'static str| std::env::var(name).map_err(|_| StoreError::MissingConfig(name));
        let endpoint = std::env::var("ACE4_BUCKET_ENDPOINT").ok();
        Ok(BucketConfig {
            path_style: endpoint.is_some(),
            endpoint,
            region: std::env::var("ACE4_BUCKET_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
            bucket: var("ACE4_BUCKET_NAME")?,
            access_key: var("ACE4_BUCKET_ACCESS_KEY")?,
            secret_key: SecretKey(var("ACE4_BUCKET_SECRET_KEY")?),
        })
    }
}

/// The bucket's secret key. Its `Debug` output hides it.
#[derive(Clone)]
pub struct SecretKey(pub String);

impl SecretKey {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<hidden>)")
    }
}
