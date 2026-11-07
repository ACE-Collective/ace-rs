//! The reads authentication needs. They come with no `Actor`, so they can't go through a permission, and
//! they're here so that `Gate` stays the only holder of the database.

use uuid::Uuid;

use super::Gate;
use crate::ServiceError;
use crate::actor::{Actor, ApiKeyId, UserId};

/// A user's row, for checking a password.
pub(crate) struct Account {
    pub(crate) id: UserId,
    pub(crate) username: String,
    pub(crate) password_hash: String,
    pub(crate) enabled: bool,
}

/// Who a stored credential stands for, and the hash to compare.
pub(crate) struct StoredCredential {
    pub(crate) actor: Actor,
    pub(crate) secret_hash: Vec<u8>,
}

impl Gate {
    pub(crate) async fn account_named(
        &self,
        username: &str,
    ) -> Result<Option<Account>, ServiceError> {
        let row = sqlx::query!(
            r#"SELECT id, username::text AS "username!", password_hash, enabled
               FROM service.users WHERE username = $1::text"#,
            username,
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|row| Account {
            id: UserId(row.id),
            username: row.username,
            password_hash: row.password_hash,
            enabled: row.enabled,
        }))
    }

    pub(crate) async fn account(&self, id: UserId) -> Result<Option<Account>, ServiceError> {
        let row = sqlx::query!(
            r#"SELECT id, username::text AS "username!", password_hash, enabled
               FROM service.users WHERE id = $1"#,
            id.0,
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|row| Account {
            id: UserId(row.id),
            username: row.username,
            password_hash: row.password_hash,
            enabled: row.enabled,
        }))
    }

    /// A session that hasn't expired, of a user who's enabled. Time is the database's.
    pub(crate) async fn live_session(
        &self,
        id: Uuid,
    ) -> Result<Option<StoredCredential>, ServiceError> {
        let row = sqlx::query!(
            r#"SELECT s.secret_hash, u.id AS user_id, u.username::text AS "username!"
               FROM service.sessions s
               JOIN service.users u ON u.id = s.user_id
               WHERE s.id = $1 AND s.expires_at > now() AND u.enabled"#,
            id,
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|row| StoredCredential {
            actor: Actor::User {
                id: UserId(row.user_id),
                name: row.username,
            },
            secret_hash: row.secret_hash,
        }))
    }

    /// A key whose owner, if it has one, is enabled.
    pub(crate) async fn usable_api_key(
        &self,
        id: ApiKeyId,
    ) -> Result<Option<StoredCredential>, ServiceError> {
        let row = sqlx::query!(
            r#"SELECT k.name, k.owner_id, k.secret_hash
               FROM service.api_keys k
               LEFT JOIN service.users u ON u.id = k.owner_id
               WHERE k.id = $1 AND (k.owner_id IS NULL OR u.enabled)"#,
            id.0,
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|row| StoredCredential {
            actor: Actor::ApiKey {
                id,
                name: row.name,
                owner: row.owner_id.map(UserId),
            },
            secret_hash: row.secret_hash,
        }))
    }
}
