//! Who is acting: a user, an API key or one of ACE's own components.
//!
//! A row stores an actor as this type's JSON, in a `service.actor` column. Its `kind` and `id` are
//! the identity, which never changes, and `Display` prints them. A name is what the user or key was
//! called at the time, kept so a row still reads the same after a rename or a deletion. Permissions
//! and audit queries go by the identity, never by a name.
//!
//! There is no `Deserialize`, so a request's body can't become an actor: an adapter builds one only
//! from what it authenticated.

use std::fmt;

use serde::Serialize;
use uuid::Uuid;

/// A user's id, the primary key of `service.users` (PLAN.md 5.4). A row that records a user as an actor
/// has no foreign key, because it has to outlive the user. This type doesn't say the user exists: only
/// `Service`'s authentication does, by returning an `Actor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

/// An API key's id, never the key itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ApiKeyId(pub Uuid);

/// The name of one of ACE's own components, such as `scheduler`, `collector:journal` or
/// `pool:parsers`. The name is the component's identity, so it stays the same between runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Component(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} isn't a component name: use lowercase letters, digits and - _ . :")]
pub struct InvalidComponent(String);

impl Component {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidComponent> {
        let name = name.into();
        let allowed = |c: char| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.' | ':')
        };
        if name.is_empty() || !name.chars().all(allowed) {
            return Err(InvalidComponent(name));
        }
        Ok(Component(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The class whose grants the component holds as well as its own, when it has one: every
    /// collector (`collector:<name>`, PLAN.md 6.1) holds what the component `collector` is granted,
    /// which migration 0074 makes `alert:create`, since a site's collector is named in the site's
    /// binary and no migration can name it, and every detection export (`export:<name>`, PLAN.md
    /// decision 58) holds what the component `export` is granted, which migration 0086 makes
    /// `detection:read` and `export:record`. A deny on the component itself still wins, as a deny always
    /// does (`permission::allows`). No other component has a class: a scheduled task, a pool or the
    /// hunter holds only its own grants.
    pub fn class(&self) -> Option<&'static str> {
        COMPONENT_CLASSES.iter().copied().find(|class| {
            self.0
                .strip_prefix(class)
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|name| !name.is_empty())
        })
    }
}

/// The component classes (`Component::class`).
const COMPONENT_CLASSES: &[&str] = &["collector", "export"];

/// Who is acting. A match on this must name every kind, so adding one fails the build wherever
/// an actor's kind matters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Actor {
    User {
        id: UserId,
        name: String,
    },
    ApiKey {
        id: ApiKeyId,
        name: String,
        /// The user the key belongs to. None for a key that stands for a service, as ace3's
        /// config keys do.
        owner: Option<UserId>,
    },
    /// One of ACE's own components, which nobody authenticated for.
    Internal {
        id: Component,
    },
}

impl fmt::Display for Actor {
    /// The actor's identity, for log lines. It holds no name, so it never changes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Actor::User { id, .. } => write!(f, "user:{}", id.0),
            Actor::ApiKey { id, .. } => write!(f, "api_key:{}", id.0),
            Actor::Internal { id } => write!(f, "internal:{}", id.0),
        }
    }
}
