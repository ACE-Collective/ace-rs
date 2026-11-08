//! A user's GUI preferences (PLAN.md 5.7), ace3's `aceapi_v2/user_preferences` and its `UserPreference`
//! model: settings an analyst picks once and keeps across browsers and logins. A view's passing state,
//! such as a list's sort order, isn't one.
//!
//! Each key has a type that checks its value, `PreferenceKey::parse`, and a default, so every key has a
//! value for every user. A stored value is checked again when it's read, so a row a later release can't
//! read falls back to the default with a warning, as ace3's does, rather than breaking the page. 5.7 brings
//! `theme`; `alert_sections` comes with 5.8 and `manage_columns` with 5.10, each as a `PreferenceKey`
//! and a `PreferenceValue` variant.
//!
//! As in ace3, a preference is the caller's own: there's no user id to name, and it needs no grant,
//! since it changes only how the caller's own pages look. Setting or resetting one goes through
//! `Gate::write_own` with an audit row; ace3 writes none. Only a user has preferences. ace3 lets an API
//! key that inherits its owner's scope change its owner's, but here every key is refused, as the rest of
//! `/me` refuses keys (`users`). A set that changes nothing and a reset of a default have no row.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::actor::Actor;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::users::as_user;
use crate::{Service, ServiceError};

/// A preference's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PreferenceKey {
    Theme,
}

impl PreferenceKey {
    /// Every key, in the order a list of them is given.
    pub const ALL: &'static [PreferenceKey] = &[PreferenceKey::Theme];

    pub fn name(self) -> &'static str {
        match self {
            PreferenceKey::Theme => "theme",
        }
    }

    /// The key with this name, or None for a name no key has.
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|key| key.name() == name)
    }

    /// What a user who never set this key has.
    pub fn default_value(self) -> PreferenceValue {
        match self {
            PreferenceKey::Theme => PreferenceValue::Theme(ThemePreference::default()),
        }
    }

    /// Checks a value for this key, as ace3's schema for it does, filling in what it leaves out. A field
    /// the key doesn't have is refused, as ace3's `extra="forbid"` is.
    pub fn parse(self, value: Value) -> Result<PreferenceValue, ServiceError> {
        let invalid = |error: serde_json::Error| {
            ServiceError::InvalidRequest(format!("not a {} preference: {error}", self.name()))
        };
        // serde would take a struct's fields from an array too.
        if !value.is_object() {
            return Err(ServiceError::InvalidRequest(format!(
                "a {} preference is a JSON object",
                self.name()
            )));
        }
        match self {
            PreferenceKey::Theme => serde_json::from_value(value)
                .map(PreferenceValue::Theme)
                .map_err(invalid),
        }
    }
}

impl std::fmt::Display for PreferenceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A preference's value, checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PreferenceValue {
    Theme(ThemePreference),
}

impl PreferenceValue {
    pub fn key(&self) -> PreferenceKey {
        match self {
            PreferenceValue::Theme(_) => PreferenceKey::Theme,
        }
    }

    /// The value as JSON, as it's stored and as the API gives it.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("a preference is JSON")
    }
}

/// ace3's `ThemePreference`: the GUI's look.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThemePreference {
    #[serde(default)]
    pub mode: Theme,
}

/// ace3's five themes. `System` follows the browser's `prefers-color-scheme`, so the page's stylesheet
/// resolves it, not the server. `Jd` is a high-contrast light theme and `Halloween` a dark one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
    Jd,
    Halloween,
}

impl Theme {
    pub const ALL: &'static [Theme] = &[
        Theme::System,
        Theme::Light,
        Theme::Dark,
        Theme::Jd,
        Theme::Halloween,
    ];

    /// The name stored, sent and put in the page.
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
            Theme::Jd => "jd",
            Theme::Halloween => "halloween",
        }
    }

    /// The theme with this name.
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|theme| theme.as_str() == name)
    }

    /// What a menu calls it: ace3's labels, without the emoji.
    pub fn label(self) -> &'static str {
        match self {
            Theme::System => "System",
            Theme::Light => "Light",
            Theme::Dark => "Dark",
            Theme::Jd => "JD",
            Theme::Halloween => "Halloween",
        }
    }
}

/// One preference of a user's, as they have it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preference {
    pub value: PreferenceValue,
    /// When the stored value last changed, or None when nothing is stored.
    pub updated_at: Option<DateTime<Utc>>,
    /// Whether this is the key's default rather than something the user set, which is also the case
    /// when the stored value is one this release can't read.
    pub is_default: bool,
}

impl Preference {
    fn default_for(key: PreferenceKey) -> Self {
        Preference {
            value: key.default_value(),
            updated_at: None,
            is_default: true,
        }
    }
}

/// A stored value in an audit row. Every variant is a closed type.
#[derive(Serialize)]
#[serde(untagged)]
enum Stored<'a> {
    Value {
        value: &'a PreferenceValue,
    },
    /// A stored value this release can't read, which a set or reset replaced.
    Unreadable {
        unreadable: bool,
    },
}

impl Recorded for Stored<'_> {}

/// A row's value checked against its key, or None when this release can't read it, with a warning.
fn read_row(user: Uuid, key: PreferenceKey, value: Value) -> Option<PreferenceValue> {
    match key.parse(value) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(%user, %key, "a stored preference can't be read, so the default applies: {error}");
            None
        }
    }
}

fn from_row(user: Uuid, key: PreferenceKey, value: Value, updated_at: DateTime<Utc>) -> Preference {
    match read_row(user, key, value) {
        Some(value) => Preference {
            value,
            updated_at: Some(updated_at),
            is_default: false,
        },
        None => Preference {
            value: key.default_value(),
            updated_at: Some(updated_at),
            is_default: true,
        },
    }
}

impl Service {
    /// Every key's preference for the caller, defaults filled in, in `PreferenceKey::ALL`'s order. Only a
    /// user has preferences; it needs no grant.
    pub async fn preferences(&self, actor: &Actor) -> Result<Vec<Preference>, ServiceError> {
        let (user, _) = as_user(actor)?;
        let user = user.0;
        let rows = self
            .gate
            .read_own(&|tx| {
                Box::pin(async move {
                    Ok(sqlx::query!(
                        "SELECT key, value, updated_at FROM service.user_preferences
                         WHERE user_id = $1",
                        user,
                    )
                    .fetch_all(tx.conn())
                    .await?)
                })
            })
            .await?;
        Ok(PreferenceKey::ALL
            .iter()
            .map(|&key| {
                // A row under a key this release doesn't have isn't given, as in ace3.
                match rows.iter().find(|row| row.key == key.name()) {
                    Some(row) => from_row(user, key, row.value.clone(), row.updated_at),
                    None => Preference::default_for(key),
                }
            })
            .collect())
    }

    /// One of the caller's preferences, the default if they never set it.
    pub async fn preference(
        &self,
        actor: &Actor,
        key: PreferenceKey,
    ) -> Result<Preference, ServiceError> {
        let (user, _) = as_user(actor)?;
        let user = user.0;
        let row = self
            .gate
            .read_own(&|tx| {
                Box::pin(async move {
                    Ok(sqlx::query!(
                        "SELECT value, updated_at FROM service.user_preferences
                         WHERE user_id = $1 AND key = $2",
                        user,
                        key.name(),
                    )
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        Ok(match row {
            Some(row) => from_row(user, key, row.value, row.updated_at),
            None => Preference::default_for(key),
        })
    }

    /// The theme a page is drawn in for this actor: the user's, or the default for anyone else, since
    /// only a user has preferences.
    pub async fn theme(&self, actor: &Actor) -> Result<Theme, ServiceError> {
        if !matches!(actor, Actor::User { .. }) {
            return Ok(Theme::default());
        }
        match self.preference(actor, PreferenceKey::Theme).await?.value {
            PreferenceValue::Theme(theme) => Ok(theme.mode),
        }
    }

    /// Stores the caller's value for its key, replacing what was there. It needs no grant. Setting the
    /// value already stored changes nothing and has no row.
    pub async fn set_preference(
        &self,
        actor: &Actor,
        value: &PreferenceValue,
    ) -> Result<Preference, ServiceError> {
        let (user, _) = as_user(actor)?;
        let (user, key) = (user.0, value.key());
        let json = value.to_json();
        let json = &json;
        self.gate
            .write_own(actor, "set_preference", &|tx| {
                Box::pin(async move {
                    let stored = sqlx::query!(
                        "SELECT value, updated_at FROM service.user_preferences
                         WHERE user_id = $1 AND key = $2 FOR UPDATE",
                        user,
                        key.name(),
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let before = stored
                        .as_ref()
                        .map(|row| (read_row(user, key, row.value.clone()), row.updated_at));
                    if let Some((Some(before), updated_at)) = &before
                        && before == value
                    {
                        return Ok(Audited::unchanged(Preference {
                            value: value.clone(),
                            updated_at: Some(*updated_at),
                            is_default: false,
                        }));
                    }
                    let updated_at = sqlx::query_scalar!(
                        "INSERT INTO service.user_preferences (user_id, key, value)
                         VALUES ($1, $2, $3)
                         ON CONFLICT (user_id, key) DO UPDATE SET value = $3, updated_at = now()
                         RETURNING updated_at",
                        user,
                        key.name(),
                        json,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let target = Target::user_preference(user, key.name());
                    let after = Stored::Value { value };
                    let change = match &before {
                        None => Change::added(target, &after)?,
                        Some((Some(before), _)) => {
                            Change::updated(target, &Stored::Value { value: before }, &after)?
                        }
                        Some((None, _)) => Change::updated(
                            target,
                            &Stored::Unreadable { unreadable: true },
                            &after,
                        )?,
                    };
                    Ok(Audited::changed(
                        Preference {
                            value: value.clone(),
                            updated_at: Some(updated_at),
                            is_default: false,
                        },
                        change,
                    ))
                })
            })
            .await
    }

    /// Forgets the caller's value for a key, so its default applies again, and returns the default. It
    /// needs no grant. A key with nothing stored changes nothing and has no row.
    pub async fn reset_preference(
        &self,
        actor: &Actor,
        key: PreferenceKey,
    ) -> Result<Preference, ServiceError> {
        let (user, _) = as_user(actor)?;
        let user = user.0;
        self.gate
            .write_own(actor, "reset_preference", &|tx| {
                Box::pin(async move {
                    let removed = sqlx::query_scalar!(
                        "DELETE FROM service.user_preferences WHERE user_id = $1 AND key = $2
                         RETURNING value",
                        user,
                        key.name(),
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(removed) = removed else {
                        return Ok(Audited::unchanged(Preference::default_for(key)));
                    };
                    let target = Target::user_preference(user, key.name());
                    let change = match read_row(user, key, removed) {
                        Some(value) => Change::removed(target, &Stored::Value { value: &value })?,
                        None => Change::removed(target, &Stored::Unreadable { unreadable: true })?,
                    };
                    Ok(Audited::changed(Preference::default_for(key), change))
                })
            })
            .await
    }
}
