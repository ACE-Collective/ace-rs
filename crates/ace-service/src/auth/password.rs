//! Passwords: Argon2id through RustCrypto's `argon2`, at OWASP's smallest recommended cost (19 MiB, two
//! passes, one lane), which suits a laptop. The cost is in each hash, so raising it here leaves old hashes
//! working.
//!
//! ace3 uses bcrypt, and upgrades werkzeug's older pbkdf2 and scrypt hashes at login. Neither matters here
//! until users move from ace3, which PLAN.md defers. That step can verify them the same way ace3 does.

use std::sync::{Arc, LazyLock};

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use tokio::sync::Semaphore;

use crate::ServiceError;

/// In KiB.
const MEMORY_COST: u32 = 19_456;
const TIME_COST: u32 = 2;
const LANES: u32 = 1;

/// How many hashes run at once, at `MEMORY_COST` each. Anyone who can reach a login can ask for a hash,
/// and `ace`'s `mem_limit` in Compose is 1 GiB, so a flood of logins queues here instead of killing it.
const HASHES_AT_ONCE: usize = 4;

/// ace3 asks for 8 characters and a special one, in its GUI's form only. ace4 has no lockout, as ace3 has
/// none, so it asks for length, which is what slows a guesser, and for nothing else.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// Longer is refused, so what's hashed stays bounded.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// A password on its way to being hashed. There's no `Display` or `Serialize`, and `Debug` hides it, so a
/// log line or an audit row can't print one by accident. `expose` is for the one place it's handed over.
pub struct Password(String);

impl Password {
    pub fn new(password: impl Into<String>) -> Self {
        Password(password.into())
    }

    /// A new password for someone to be told once: 192 random bits as hex.
    pub fn generate() -> Result<Self, ServiceError> {
        let mut bytes = [0_u8; 24];
        getrandom::fill(&mut bytes)
            .map_err(|error| ServiceError::Hashing(format!("reading randomness: {error}")))?;
        Ok(Password(hex::encode(bytes)))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether this may become someone's password. A login doesn't ask.
    pub(super) fn check_strength(&self) -> Result<(), ServiceError> {
        if self.0.chars().count() < MIN_PASSWORD_CHARS || self.0.len() > MAX_PASSWORD_BYTES {
            return Err(ServiceError::WeakPassword);
        }
        Ok(())
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password([hidden])")
    }
}

fn hasher() -> Result<Argon2<'static>, ServiceError> {
    let params = Params::new(MEMORY_COST, TIME_COST, LANES, None)
        .map_err(|error| ServiceError::Hashing(error.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_now(password: &[u8]) -> Result<String, ServiceError> {
    hasher()?
        .hash_password(password)
        .map(|hash| hash.to_string())
        .map_err(|error| ServiceError::Hashing(error.to_string()))
}

/// What a login with no stored hash verifies against, so it costs what a wrong password costs. Nothing
/// can match it: it's the hash of a random password that's thrown away.
static NOBODY: LazyLock<Result<String, String>> = LazyLock::new(|| {
    let password = Password::generate().map_err(|error| error.to_string())?;
    hash_now(password.expose().as_bytes()).map_err(|error| error.to_string())
});

/// Verifies in constant time, which the crate's comparison of its output does. A password too long to
/// have been stored is still hashed up to the limit, so it takes as long as any other.
fn verify_now(stored: Option<&str>, password: &[u8]) -> Result<bool, ServiceError> {
    let nobody;
    let (hash, can_match) = match stored {
        Some(hash) => (hash, true),
        None => {
            nobody = NOBODY
                .as_ref()
                .map_err(|error| ServiceError::Hashing(error.clone()))?;
            (nobody.as_str(), false)
        }
    };
    let candidate = &password[..password.len().min(MAX_PASSWORD_BYTES)];
    let matches = hasher()?.verify_password(candidate, hash).is_ok();
    Ok(matches && can_match && password.len() <= MAX_PASSWORD_BYTES)
}

/// Runs hashes off the async threads, a few at a time.
#[derive(Debug, Clone)]
pub(crate) struct Passwords {
    slots: Arc<Semaphore>,
}

impl Passwords {
    pub(crate) fn new() -> Self {
        Passwords {
            slots: Arc::new(Semaphore::new(HASHES_AT_ONCE)),
        }
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, ServiceError> + Send + 'static,
    ) -> Result<T, ServiceError> {
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|error| ServiceError::Hashing(error.to_string()))?;
        // The hash keeps its slot until it ends, even if the request that asked for it has gone, or a
        // client hanging up could get past the limit.
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            work()
        })
        .await
        .map_err(|error| ServiceError::Hashing(error.to_string()))?
    }

    /// The PHC string to store for a password that passed `check_strength`.
    pub(super) async fn hash(&self, password: Password) -> Result<String, ServiceError> {
        password.check_strength()?;
        self.run(move || hash_now(password.expose().as_bytes()))
            .await
    }

    /// Whether `password` is the one `stored` was made from. With nothing stored the answer is no, after
    /// doing the same work, so a caller can't tell an unknown user by the time this takes.
    pub(super) async fn verify(
        &self,
        stored: Option<String>,
        password: Password,
    ) -> Result<bool, ServiceError> {
        self.run(move || verify_now(stored.as_deref(), password.expose().as_bytes()))
            .await
    }
}
