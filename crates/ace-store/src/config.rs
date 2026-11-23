//! Where the bucket is and how to reach it.

use crate::StoreError;
use crate::aws::Access;

/// The bucket's endpoint and name, and how the client signs in.
#[derive(Debug, Clone)]
pub struct BucketConfig {
    /// An S3-compatible server's URL, such as `http://bucket:8333`. None means AWS S3 itself.
    pub endpoint: Option<String>,
    pub bucket: String,
    /// Static keys or the AWS credential chain, and the region (`crate::aws`).
    pub access: Access,
    /// Path-style URLs (`endpoint/bucket/key`), which S3-compatible servers want, rather than
    /// a host name per bucket.
    pub path_style: bool,
}

/// The variable holding the bucket's static access key.
pub const ACCESS_KEY_VARIABLE: &str = "ACE_RS_BUCKET_ACCESS_KEY";
/// The variable holding that key's secret.
pub const SECRET_KEY_VARIABLE: &str = "ACE_RS_BUCKET_SECRET_KEY";

impl BucketConfig {
    /// `ACE_RS_BUCKET_NAME`, and optionally `ACE_RS_BUCKET_ENDPOINT`, `ACE_RS_BUCKET_REGION`,
    /// `ACE_RS_BUCKET_ACCESS_KEY` and `ACE_RS_BUCKET_SECRET_KEY`. With an endpoint, URLs are path-style.
    /// With both keys the client signs with them; with neither, with the AWS credential chain (the
    /// EC2 instance role, for one); with one, this fails. Without a region, the region chain's is
    /// used, else `us-east-1`. An empty variable counts as not set.
    pub fn from_env() -> Result<Self, StoreError> {
        let optional = |name: &str| std::env::var(name).ok();
        let endpoint = optional("ACE_RS_BUCKET_ENDPOINT").filter(|e| !e.is_empty());
        Ok(BucketConfig {
            path_style: endpoint.is_some(),
            endpoint,
            bucket: std::env::var("ACE_RS_BUCKET_NAME")
                .map_err(|_| StoreError::MissingConfig("ACE_RS_BUCKET_NAME"))?,
            access: Access::from_parts(
                optional(ACCESS_KEY_VARIABLE),
                optional(SECRET_KEY_VARIABLE),
                optional("ACE_RS_BUCKET_REGION"),
                (ACCESS_KEY_VARIABLE, SECRET_KEY_VARIABLE),
            )?,
        })
    }
}
