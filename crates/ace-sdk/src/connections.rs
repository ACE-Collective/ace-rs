//! Shared connections: one named connection to a service in the site overlay, which many components
//! of an integration name, as one of ace3's config sections (`mail_api`, `endpoint_vendor`,
//! `virus_total`, `example_cloud`) serves every module, probe, command type and AI backend of its integration.
//!
//! ```yaml
//! connections:
//!   graph_readonly:
//!     type: mail_api
//!     settings:
//!       tenant_id: 6f1c2a8e-0b7d-4e3a-9c55-2d4f8a1b3c70
//!       client_id: 0d7e4c1a-5b2f-4a90-8e63-1c9b7f2a4d58
//!       request_timeout_seconds: 10
//!     secrets:
//!       certificate: mail_api_readonly_certificate
//!       certificate_password: mail_api_readonly_certificate_password
//! modules:
//!   entra_user:
//!     connections:
//!       mail_api: graph_readonly
//! secrets:
//!   mail_api_readonly_certificate: env:ACE4_MAIL_API_READONLY_CERTIFICATE
//!   mail_api_readonly_certificate_password: env:ACE4_MAIL_API_READONLY_CERTIFICATE_PASSWORD
//! ```
//!
//! **A connection type** ([`ConnectionType`]) is what an integration declares for its service: its
//! name (the `type` a connection gives), its settings type, the secrets a connection of it may name,
//! by their role (`certificate`, `api_key`), and which of its settings change what a component finds
//! through it ([`ConnectionType::identity`]). A connection is checked against its type wherever it is
//! read, with its path in the error, and a connection whose type no component of the binary takes
//! stops `ace` before any command runs.
//!
//! **A slot** ([`ConnectionSlot`]) is where a component takes a connection of one type, by a name of
//! its own (`mail_api`). A lookup module declares its slots in `Module::CONNECTIONS`, an action handler
//! in `ActionSpec::connections`, and a collector, a correlation command type or an AI backend type in
//! what `ace_app::App` registers it with. The component's overlay section binds each slot to a
//! connection with `connections: {<slot>: <connection>}`; a slot it doesn't bind has no connection,
//! so a module runs on its settings type's default for it and has none of its secrets.
//!
//! **What a component holds.** The connection's settings, checked against its type, and the
//! connection's secrets and no others, by role ([`Connections`]): a process resolves the secrets of
//! the connections its own components name, and only those (PLAN.md 2.24). A lookup module also gets
//! the settings inside its own settings block, under the slot's name, so `Module::init` builds its
//! client from them as it would from settings of its own; its own block may not set that key.
//!
//! **The analysis cache** (PLAN.md decision 26) keys a module's result on its own settings block
//! without the slots' keys, and on each bound slot's connection type and *identity*: the part of the
//! connection's settings that changes what a lookup finds, such as a tenant, and not what only changes
//! how it asks, such as a timeout (`crate::cache::KeyParts::connections`). A type that leaves
//! [`ConnectionType::identity`] at its default keys on every setting it has.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::context::{Secret, Secrets};
use crate::manifest::{SettingsError, load_settings};
use crate::module::Settings;

/// A connection type an integration declares: the service, how a connection to it is configured,
/// and what of that changes what is found through it.
pub trait ConnectionType: 'static {
    /// The type's name, as a connection's `type` gives it, such as `mail_api`.
    const NAME: &'static str;
    /// The secrets a connection of this type may name, by role, such as `certificate`. A connection
    /// names a secret of the overlay's `secrets:` for each role it fills; a role it leaves out isn't
    /// held.
    const SECRETS: &'static [&'static str] = &[];
    /// A connection's settings. Missing settings fall back to `Default`, and an unknown key is
    /// refused, as a module's are.
    type Settings: Settings + serde::Serialize;

    /// What of a connection's settings changes what a component finds through it, which a cached
    /// result's key holds: a tenant or an account, not a timeout. Every setting by default.
    fn identity(settings: &Self::Settings) -> Value {
        serde_json::to_value(settings).unwrap_or(Value::Null)
    }

    /// The TCP ports a connection with these settings reaches beyond its components' own, such as
    /// a proxy's (PLAN.md decision 35): a pool whose components bind the connection is let reach
    /// them too. None by default.
    fn tcp_ports(_settings: &Self::Settings) -> Vec<u16> {
        Vec::new()
    }
}

/// A connection type without its Rust type, as a manifest or a spec holds it.
#[derive(Clone, Copy)]
pub struct ConnectionKind {
    /// `ConnectionType::NAME`.
    pub name: &'static str,
    /// `ConnectionType::SECRETS`.
    pub secrets: &'static [&'static str],
    check: fn(Option<&Value>) -> Result<(), SettingsError>,
    identity: fn(Option<&Value>) -> Result<Value, SettingsError>,
    tcp_ports: fn(Option<&Value>) -> Result<Vec<u16>, SettingsError>,
}

impl ConnectionKind {
    pub const fn of<T: ConnectionType>() -> ConnectionKind {
        ConnectionKind {
            name: T::NAME,
            secrets: T::SECRETS,
            check: check::<T>,
            identity: identity::<T>,
            tcp_ports: ports_of::<T>,
        }
    }

    /// The ports a connection with `block` reaches (`ConnectionType::tcp_ports`).
    pub fn tcp_ports(&self, block: Option<&Value>) -> Result<Vec<u16>, SettingsError> {
        (self.tcp_ports)(block)
    }

    /// Checks a connection's settings block against the type.
    pub fn check(&self, block: Option<&Value>) -> Result<(), SettingsError> {
        (self.check)(block)
    }

    /// The identity of a connection with `block` (`ConnectionType::identity`).
    pub fn identity(&self, block: Option<&Value>) -> Result<Value, SettingsError> {
        (self.identity)(block)
    }
}

impl std::fmt::Debug for ConnectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionKind")
            .field("name", &self.name)
            .field("secrets", &self.secrets)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ConnectionKind {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.secrets == other.secrets
    }
}

impl Eq for ConnectionKind {}

fn check<T: ConnectionType>(block: Option<&Value>) -> Result<(), SettingsError> {
    load_settings::<T::Settings>(block).map(drop)
}

fn identity<T: ConnectionType>(block: Option<&Value>) -> Result<Value, SettingsError> {
    load_settings::<T::Settings>(block).map(|settings| T::identity(&settings))
}

fn ports_of<T: ConnectionType>(block: Option<&Value>) -> Result<Vec<u16>, SettingsError> {
    load_settings::<T::Settings>(block).map(|settings| T::tcp_ports(&settings))
}

/// Where a component takes a connection of one type, by a name of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionSlot {
    /// The slot's name, as the component's `connections:` binds it, and, for a lookup module, the
    /// key of its settings block the connection's settings go under.
    pub name: &'static str,
    pub kind: ConnectionKind,
}

impl ConnectionSlot {
    pub const fn of<T: ConnectionType>(name: &'static str) -> ConnectionSlot {
        ConnectionSlot {
            name,
            kind: ConnectionKind::of::<T>(),
        }
    }
}

/// One of the overlay's `connections:`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSection {
    /// The connection type, as an integration names it (`ConnectionType::NAME`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Checked against the type's settings; null when left out, which is the type's defaults.
    #[serde(default)]
    pub settings: Option<Value>,
    /// The secret of the overlay's `secrets:` for each role of the type's it fills.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
}

/// A slot bound to a connection, checked: what a process resolves and gives the component.
#[derive(Debug, Clone, PartialEq)]
pub struct Binding {
    /// The component's slot.
    pub slot: String,
    /// The connection's name in the overlay.
    pub connection: String,
    /// Its type's name.
    pub kind: &'static str,
    /// Its settings block, as the overlay writes it.
    pub settings: Option<Value>,
    /// What of its settings a cached result's key holds (`ConnectionType::identity`).
    pub identity: Value,
    /// The secret of the overlay's `secrets:` for each role it fills.
    pub secrets: BTreeMap<String, String>,
    /// The TCP ports it reaches beyond its component's own (`ConnectionType::tcp_ports`), which a
    /// pool that runs the component allows.
    pub tcp_ports: Vec<u16>,
}

/// The ports `bindings` reach beyond their components' own, each once, in order.
pub fn tcp_ports(bindings: &[Binding]) -> Vec<u16> {
    let ports: std::collections::BTreeSet<u16> = bindings
        .iter()
        .flat_map(|b| b.tcp_ports.iter().copied())
        .collect();
    ports.into_iter().collect()
}

/// The names in the overlay's `secrets:` that `bindings` use, each once, in order: the only
/// connection secrets a process that runs their component resolves.
pub fn secret_names(bindings: &[Binding]) -> Vec<&str> {
    let names: std::collections::BTreeSet<&str> = bindings
        .iter()
        .flat_map(|binding| binding.secrets.values().map(String::as_str))
        .collect();
    names.into_iter().collect()
}

/// A connection as a component holds it: its settings and its secrets, by role.
#[derive(Debug, Clone, Default)]
pub struct Connection {
    /// Its name in the overlay.
    pub name: String,
    /// Its type's name.
    pub kind: String,
    /// Its settings block, checked against its type when the overlay was read.
    pub settings: Option<Value>,
    secrets: Secrets,
}

impl Connection {
    /// A connection named `name` of the type `kind` with `settings` and no secrets, as a test gives a
    /// component one; a pool makes them with `Connections::resolve`.
    pub fn new(name: &str, kind: &str, settings: Option<Value>) -> Connection {
        Connection {
            name: name.to_owned(),
            kind: kind.to_owned(),
            settings,
            secrets: Secrets::new(),
        }
    }

    /// The connection with `value` filling `role`.
    pub fn with_secret(mut self, role: &str, value: Secret) -> Connection {
        self.secrets = self.secrets.with(role, value);
        self
    }

    /// The secret that fills `role`, when the connection names one and the process resolved it.
    pub fn secret(&self, role: &str) -> Option<&Secret> {
        self.secrets.get(role)
    }

    /// The roles whose secrets are held.
    pub fn secret_roles(&self) -> Vec<&str> {
        self.secrets.names()
    }
}

/// A component's connections, by slot.
#[derive(Debug, Clone, Default)]
pub struct Connections(BTreeMap<String, Connection>);

impl Connections {
    pub fn new() -> Connections {
        Connections::default()
    }

    /// The connections of `bindings`, each with its secrets from `secrets`, the process's resolved
    /// ones, by role. A secret the process couldn't resolve isn't held; its pool logged it.
    pub fn resolve(bindings: &[Binding], secrets: &Secrets) -> Connections {
        Connections(
            bindings
                .iter()
                .map(|binding| {
                    let held = binding
                        .secrets
                        .iter()
                        .filter_map(|(role, name)| {
                            secrets.get(name).map(|value| (role.clone(), value.clone()))
                        })
                        .fold(Secrets::new(), |held, (role, value)| held.with(role, value));
                    let connection = Connection {
                        name: binding.connection.clone(),
                        kind: binding.kind.to_owned(),
                        settings: binding.settings.clone(),
                        secrets: held,
                    };
                    (binding.slot.clone(), connection)
                })
                .collect(),
        )
    }

    /// Adds `connection` at `slot`, as a test gives a component one.
    pub fn with(mut self, slot: &str, connection: Connection) -> Connections {
        self.0.insert(slot.to_owned(), connection);
        self
    }

    /// The connection bound to `slot`.
    pub fn get(&self, slot: &str) -> Option<&Connection> {
        self.0.get(slot)
    }

    /// The slots bound, in order.
    pub fn slots(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }

    /// The settings of the connection bound to `slot`, as `T`'s: an error says the slot has none,
    /// or one of another type.
    pub fn settings<T: ConnectionType>(&self, slot: &str) -> Result<T::Settings, String> {
        let connection = self
            .get(slot)
            .ok_or_else(|| format!("no connection is bound to the slot {slot}"))?;
        if connection.kind != T::NAME {
            return Err(format!(
                "the connection {} bound to the slot {slot} is of type {}, not {}",
                connection.name,
                connection.kind,
                T::NAME
            ));
        }
        load_settings::<T::Settings>(connection.settings.as_ref())
            .map_err(|e| format!("the connection {}'s settings: {e}", connection.name))
    }

    /// The secret that fills `role` of the connection bound to `slot`, when there is one.
    pub fn secret(&self, slot: &str, role: &str) -> Option<&Secret> {
        self.get(slot)?.secret(role)
    }
}

/// How a connection is named: lowercase letters, digits and `_`, as an instance is.
pub fn is_connection_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Why `connection` can't be used as `kind`, saying where: its settings or a role it fills.
pub fn check_section(
    name: &str,
    section: &ConnectionSection,
    kind: &ConnectionKind,
) -> Result<Value, (String, String)> {
    let path = format!("connections.{name}");
    if section.kind != kind.name {
        return Err((
            format!("{path}.type"),
            format!("is {:?}, not {:?}", section.kind, kind.name),
        ));
    }
    kind.check(section.settings.as_ref())
        .map_err(|e| (format!("{path}.settings"), e.to_string()))?;
    if let Some(role) = section
        .secrets
        .keys()
        .find(|role| !kind.secrets.contains(&role.as_str()))
    {
        return Err((
            format!("{path}.secrets.{role}"),
            format!(
                "a connection of type {} has no secret {role:?}; its secrets are {:?}",
                kind.name, kind.secrets
            ),
        ));
    }
    kind.identity(section.settings.as_ref())
        .map_err(|e| (format!("{path}.settings"), e.to_string()))
}
