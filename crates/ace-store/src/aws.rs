//! Where an AWS client's credentials and region come from: the bucket's, and a site's own AWS
//! clients (a queue, another bucket) built the same way.
//!
//! Static keys, when they are given, sign every request, and nothing else is read: no `AWS_*`
//! variable, no `~/.aws` file, no metadata service. This is how the dev and e2e stacks reach their
//! bucket. Without them the credentials come from the AWS SDK's default chain, in its order:
//!
//! 1. the environment: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`;
//! 2. the shared config and credentials files (`~/.aws/config`, `~/.aws/credentials`, or
//!    `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`), for `AWS_PROFILE` or `default`,
//!    including a profile that assumes a role;
//! 3. a web identity token (`AWS_WEB_IDENTITY_TOKEN_FILE` with `AWS_ROLE_ARN`), as EKS gives a pod;
//! 4. the ECS container endpoint (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `_FULL_URI`);
//! 5. the EC2 instance metadata service (IMDSv2), which gives the instance role's credentials.
//!
//! The chain is `aws-config`'s, without its SSO, login and `credential_process` sources, which an
//! unattended server has no use for. It is built on the first request, so a client can be made
//! without waiting, and the SDK client caches what it returns and asks again before it expires.
//!
//! The region, when it isn't given, comes from the SDK's region chain: `AWS_REGION` (or
//! `AWS_DEFAULT_REGION`), the profile's `region`, then the instance metadata service. With none
//! found it is [`DEFAULT_REGION`], the bucket's region before the chain was added.

use std::fmt;
use std::sync::Arc;

use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::default_provider::region::DefaultRegionChain;
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::Credentials;
use aws_credential_types::provider::{
    ProvideCredentials, SharedCredentialsProvider, future as provider_future,
};
use tokio::sync::OnceCell;

use crate::StoreError;

/// The region used when none is given and the chain finds none.
pub const DEFAULT_REGION: &str = "us-east-1";

/// The name static credentials carry in the SDK's logs.
const PROVIDER_NAME: &str = "ace4";

/// A static access key and its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticKeys {
    pub access_key: String,
    pub secret_key: SecretKey,
}

/// A secret key. Its `Debug` output hides it.
#[derive(Clone, PartialEq, Eq)]
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

/// How an AWS client signs in and which region it is in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    /// Static keys, or None for the credential chain.
    pub keys: Option<StaticKeys>,
    /// The region, or None for the region chain.
    pub region: Option<String>,
}

impl Access {
    /// Static keys when both are given, the chain when neither is, and an error naming the one
    /// that's missing otherwise. An empty value counts as not given. `names` are what the two
    /// are called where they come from, for that error: variables, or a site's secrets.
    pub fn from_parts(
        access_key: Option<String>,
        secret_key: Option<String>,
        region: Option<String>,
        names: (&'static str, &'static str),
    ) -> Result<Access, StoreError> {
        let given = |value: Option<String>| value.filter(|v| !v.is_empty());
        let keys = match (given(access_key), given(secret_key)) {
            (Some(access_key), Some(secret_key)) => Some(StaticKeys {
                access_key,
                secret_key: SecretKey(secret_key),
            }),
            (None, None) => None,
            (Some(_), None) => return Err(StoreError::MissingConfig(names.1)),
            (None, Some(_)) => return Err(StoreError::MissingConfig(names.0)),
        };
        Ok(Access {
            keys,
            region: given(region),
        })
    }

    /// The credentials provider: the static keys, or the chain. It needs no runtime to make; the
    /// chain is built on its first use. `region` is what the chain's STS calls (web identity, a
    /// profile's assumed role) use, the client's own region; with None they find their own.
    pub fn credentials(&self, region: Option<Region>) -> SharedCredentialsProvider {
        match &self.keys {
            Some(keys) => SharedCredentialsProvider::new(Credentials::new(
                &keys.access_key,
                keys.secret_key.expose(),
                None,
                None,
                PROVIDER_NAME,
            )),
            None => SharedCredentialsProvider::new(LazyChain {
                region,
                chain: Arc::new(OnceCell::new()),
            }),
        }
    }

    /// The region given, else the region chain's, else [`DEFAULT_REGION`].
    pub async fn region(&self) -> Region {
        if let Some(region) = &self.region {
            return Region::new(region.clone());
        }
        match DefaultRegionChain::builder().build().region().await {
            Some(region) => region,
            None => {
                tracing::warn!(
                    "no AWS region is set and the region chain found none; using {DEFAULT_REGION}"
                );
                Region::new(DEFAULT_REGION)
            }
        }
    }

    /// An SDK config holding only the region and the credentials, from which any AWS SDK client of
    /// the same release is made (`aws_sdk_sqs::Config::from(&config)`, then that client's own
    /// timeouts, retries and endpoint). Unlike `aws_config::load_defaults`, it reads no endpoint,
    /// retry, timeout or other setting from the environment or the profile.
    pub async fn sdk_config(&self) -> SdkConfig {
        let region = self.region().await;
        SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(self.credentials(Some(region.clone())))
            .region(region)
            .build()
    }

    /// Where the credentials come from, for a log line: never the keys themselves.
    pub fn source(&self) -> &'static str {
        if self.keys.is_some() {
            "static keys"
        } else {
            "the AWS credential chain"
        }
    }
}

/// The SDK's default chain, built when it is first asked for credentials.
#[derive(Debug, Clone)]
struct LazyChain {
    region: Option<Region>,
    chain: Arc<OnceCell<DefaultCredentialsChain>>,
}

impl ProvideCredentials for LazyChain {
    fn provide_credentials<'a>(&'a self) -> provider_future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        provider_future::ProvideCredentials::new(async move {
            let chain = self
                .chain
                .get_or_init(|| async {
                    let mut builder = DefaultCredentialsChain::builder();
                    if let Some(region) = &self.region {
                        builder = builder.region(region.clone());
                    }
                    builder.build().await
                })
                .await;
            chain.provide_credentials().await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMES: (&str, &str) = ("KEY", "SECRET");

    #[test]
    fn both_keys_are_static_neither_is_the_chain() {
        let access = Access::from_parts(
            Some("id".into()),
            Some("secret".into()),
            Some("eu-west-1".into()),
            NAMES,
        )
        .expect("static keys");
        assert_eq!(
            access.keys,
            Some(StaticKeys {
                access_key: "id".into(),
                secret_key: SecretKey("secret".into())
            })
        );
        assert_eq!(access.region.as_deref(), Some("eu-west-1"));
        assert_eq!(access.source(), "static keys");

        let access = Access::from_parts(None, Some(String::new()), Some(String::new()), NAMES)
            .expect("the chain");
        assert_eq!(access, Access::default());
        assert_eq!(access.source(), "the AWS credential chain");
    }

    #[test]
    fn one_key_without_the_other_names_the_missing_one() {
        let error = Access::from_parts(Some("id".into()), None, None, NAMES).unwrap_err();
        assert!(
            matches!(error, StoreError::MissingConfig("SECRET")),
            "{error}"
        );
        let error =
            Access::from_parts(Some(String::new()), Some("s".into()), None, NAMES).unwrap_err();
        assert!(matches!(error, StoreError::MissingConfig("KEY")), "{error}");
    }

    #[test]
    fn the_secret_key_is_hidden() {
        let access = Access::from_parts(Some("id".into()), Some("hunter2".into()), None, NAMES)
            .expect("static keys");
        assert!(!format!("{access:?}").contains("hunter2"));
    }

    #[tokio::test]
    async fn static_keys_are_what_the_provider_gives() {
        let access = Access::from_parts(Some("id".into()), Some("secret".into()), None, NAMES)
            .expect("static keys");
        let credentials = access
            .credentials(None)
            .provide_credentials()
            .await
            .expect("credentials");
        assert_eq!(credentials.access_key_id(), "id");
        assert_eq!(credentials.secret_access_key(), "secret");
        assert_eq!(credentials.session_token(), None);
    }

    #[tokio::test]
    async fn a_given_region_is_used_as_it_is() {
        let access = Access {
            keys: None,
            region: Some("ap-southeast-2".into()),
        };
        assert_eq!(access.region().await.as_ref(), "ap-southeast-2");
        let config = access.sdk_config().await;
        assert_eq!(config.region().map(|r| r.as_ref()), Some("ap-southeast-2"));
        assert!(config.credentials_provider().is_some());
    }
}
