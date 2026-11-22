//! A Splunk instance as a shared connection (`ace_sdk::connections`, PLAN.md decision 41): ace3's
//! `splunk_config_<name>` section, named as ace3 names the instance.
//!
//! ```yaml
//! connections:
//!   default:
//!     type: splunk
//!     settings: {host: splunk.example.com, username: ace, timezone: GMT}
//!     secrets: {password: splunk_default_password}
//! ```
//!
//! Its secrets keep ace3's names, `splunk_<instance>_password` and `splunk_<instance>_token`, filling
//! the roles `password` (with a `username`) and `token` (without one).
//!
//! Who takes one: the two Splunk modules, a Splunk correlation query source and the Splunk AI
//! backend each bind the slot [`SLOT`] to one instance (`connections: {splunk: default}`, ace3's
//! `api_name`, `config_name` and `splunk_config`); Splunk's hunt search takes every instance by its
//! own name ([`BY_NAME`]), which a hunt's `splunk_config` picks.

use std::path::PathBuf;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::search::{Connection, SearchClient};

/// The connection type `splunk`.
pub struct Splunk;

/// The role of the password a connection with a `username` logs in with.
pub const PASSWORD: &str = "password";
/// The role of the token a connection without a `username` sends.
pub const TOKEN: &str = "token";

/// The slot of a component that talks to one Splunk instance.
pub const SLOT: ace_sdk::ConnectionSlot = ace_sdk::ConnectionSlot::of::<Splunk>("splunk");

/// The slot of a component that takes every Splunk instance by its name: Splunk's hunt search.
pub const BY_NAME: ace_sdk::ConnectionSlot = ace_sdk::ConnectionSlot::by_name::<Splunk>("splunk");

/// A Splunk instance's settings, ace3's `splunk_config_<name>` without its secrets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Instance {
    /// The host, which the web UI's links and a hunt alert's `tool_instance` name.
    pub host: String,
    /// splunkd's management port.
    pub port: u16,
    /// The management API, by default `https://<host>:<port>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// The user to log in as with the `password` secret; without one, requests carry the `token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The timezone searches' times are written in, such as `GMT`.
    pub timezone: String,
    /// A PEM file of CA certificates to trust besides the platform's. Certificates are always
    /// verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<PathBuf>,
    /// The timeout of each request to splunkd.
    pub request_timeout_seconds: u64,
    /// How long a hunt's or a correlation's job may wait to start.
    pub dispatch_timeout_seconds: u64,
    /// The owner and app searches run as, ace3's `user_context` and `app_context`, unless what
    /// runs the search names its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_context: Option<String>,
}

impl Default for Instance {
    /// ace3's `splunk_config_default`, on splunkd's own port.
    fn default() -> Self {
        Instance {
            host: "localhost".to_owned(),
            port: 8089,
            base_url: None,
            username: None,
            timezone: "GMT".to_owned(),
            ca_certificates: None,
            request_timeout_seconds: 60,
            dispatch_timeout_seconds: 900,
            user_context: None,
            app_context: None,
        }
    }
}

impl Instance {
    /// The management API: `base_url`, or `https://<host>:<port>`.
    pub fn base_url(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| format!("https://{}:{}", self.host, self.port))
    }

    /// The timezone searches are written in.
    pub fn tz(&self) -> Result<chrono_tz::Tz, String> {
        self.timezone
            .parse()
            .map_err(|e| format!("timezone {:?}: {e}", self.timezone))
    }

    /// A client of the instance that logs in with `connection`'s secret: its password with a
    /// `username`, its token without one. One it doesn't hold is left out, so a search fails to
    /// log in, and `ace serve`, which holds none, can build a client it never searches with.
    pub fn client(&self, connection: &ace_sdk::Connection) -> Result<SearchClient, String> {
        let secret = |role: &str| connection.secret(role).map(|s| s.expose().to_owned());
        SearchClient::new(Connection {
            base_url: self.base_url(),
            username: self.username.clone(),
            password: secret(PASSWORD),
            token: secret(TOKEN),
            ca_certificates: self.ca_certificates.clone(),
            request_timeout: Duration::from_secs(self.request_timeout_seconds),
        })
    }
}

impl ace_sdk::ConnectionType for Splunk {
    const NAME: &'static str = "splunk";
    const SECRETS: &'static [&'static str] = &[PASSWORD, TOKEN];
    type Settings = Instance;

    /// Which instance is asked, as whom, and in which timezone a search's times are written
    /// change what is found; how long a request may wait doesn't.
    fn identity(instance: &Instance) -> serde_json::Value {
        serde_json::json!({
            "base_url": instance.base_url(),
            "username": instance.username,
            "timezone": instance.timezone,
            "user_context": instance.user_context,
            "app_context": instance.app_context,
        })
    }
}

/// The instance settings of the connection `connection`, which must be of type `splunk`.
pub fn instance_of(connection: &ace_sdk::Connection) -> Result<Instance, String> {
    if connection.kind != <Splunk as ace_sdk::ConnectionType>::NAME {
        return Err(format!(
            "the connection {} is of type {}, not splunk",
            connection.name, connection.kind
        ));
    }
    ace_sdk::manifest::load_settings::<Instance>(connection.settings.as_ref())
        .map_err(|e| format!("the connection {}'s settings: {e}", connection.name))
}
