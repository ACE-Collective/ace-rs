//! API keys and session ids: a token of `<kind>_<id>_<secret>`, shown once.
//!
//! The id is a public selector: it's the row's primary key, and it's what an audit row or a log line
//! names. The secret is 256 random bits, so a plain SHA-256 is enough, and the row stores the hash of the
//! whole token. Hashing the kind with it means one kind's token can't stand for the other. A lookup goes
//! by the id, and only then compares the hash, so the comparison is the one place a secret meets a
//! stored value, and it's in constant time.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::ServiceError;

#[derive(Debug, Clone, Copy)]
pub(super) enum Kind {
    ApiKey,
    Session,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Kind::ApiKey => "ace4k",
            Kind::Session => "ace4s",
        }
    }
}

/// A token just made, for the caller to hand over once. Nothing can read it back afterwards. There's no
/// `Display` or `Serialize`, and `Debug` hides it.
pub struct IssuedToken(String);

impl IssuedToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuedToken([hidden])")
    }
}

/// A token's hash. It has no `PartialEq`, so `==` can't compare one: `matches` is the only way.
pub(super) struct TokenHash([u8; 32]);

impl TokenHash {
    fn of(token: &str) -> Self {
        TokenHash(Sha256::digest(token.as_bytes()).into())
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(super) fn matches(&self, stored: &[u8]) -> bool {
        self.0.as_slice().ct_eq(stored).into()
    }
}

pub(super) struct Minted {
    pub(super) id: Uuid,
    pub(super) token: IssuedToken,
    pub(super) hash: TokenHash,
}

pub(super) fn mint(kind: Kind) -> Result<Minted, ServiceError> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| ServiceError::Hashing(format!("reading randomness: {error}")))?;
    let id = Uuid::new_v4();
    let token = format!("{}_{}_{}", kind.prefix(), id.simple(), hex::encode(secret));
    let hash = TokenHash::of(&token);
    Ok(Minted {
        id,
        token: IssuedToken(token),
        hash,
    })
}

/// The id and hash a presented token claims, or None if it isn't this kind's shape.
pub(super) fn parse(kind: Kind, presented: &str) -> Option<(Uuid, TokenHash)> {
    let rest = presented.strip_prefix(kind.prefix())?.strip_prefix('_')?;
    let (id, secret) = rest.split_once('_')?;
    if id.len() != 32 || secret.len() != 64 {
        return None;
    }
    let id = Uuid::try_parse(id).ok()?;
    Some((id, TokenHash::of(presented)))
}
