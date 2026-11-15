//! What the AI investigation API's process may hold, checked when it starts: ace3's
//! `aceapi_ai/startup_checks.py`.
//!
//! The process an AI agent's key talks to should hold nothing of value to the rest of ACE. ace3 makes
//! that a property the container asserts at boot, not one a reviewer has to keep true, and refuses
//! to start when it doesn't hold. `ace serve-ai` does the same, with every failure in one message.
//!
//! | ace3's check | here | what it refuses |
//! |---|---|---|
//! | `check_no_encryption_capability`: `SAQ_ENC` is set | [`check_no_encryption_capability`] | `ACE4_ENCRYPTION_KEY` in the environment, set or empty |
//! | the same: the encryption subsystem is unlocked | the same | a database role that can read the email archive, which that key seals |
//! | `check_local_overlay_skipped`: the dev overlay would merge in | [`check_overlay_is_its_own`] | an overlay with any section but the process's own |
//! | `check_infra_secrets_neutralized`: the node-to-node API key | [`check_infra_secrets`] | the lease API's pool and admin tokens, or a main API key, in the environment |
//! | the same: the GUI's signing key | the same | a database role that can read a GUI session |
//! | `check_backend_credentials` | `crate::ai::surface`, whose error is a failure here | an enabled backend that can't be built, such as one without its credential |
//! | `check_secret_literal_allowlist` | [`check_secret_allowlist`] | a secret of the overlay's `secrets:` that this process can read and no enabled backend lists |
//! | `advisory_plaintext_sweep` (a warning) | [`advisory_sweep`] | nothing: it warns of a setting that looks like a credential written in the overlay |
//! | none | [`check_no_bucket_credential`] | the bucket's access key or secret key: the API reads no file |
//! | none | [`check_role`] | a database role that can do more than migration 0064 grants, or less |
//!
//! Where each differs from ace3's, and why:
//!
//! - **The encryption capability.** ace3 unlocks a secrets table with a password. ace4 has no such
//!   table: `ACE4_ENCRYPTION_KEY` is the email archive's key, which only `ace serve` holds, and the
//!   variable is its only source. So the capability is the variable, and, apart from it, whether the
//!   process's database role can read the archive's rows at all.
//! - **The local overlay.** ace3's dev overlay, `etc/saq.yaml`, may hold live credentials and merges
//!   into every container unless `SAQ_SKIP_LOCAL_SAQ_YAML` is set; the AI container's only
//!   configuration is `etc/saq.ai.yaml`. ace4 reads one overlay and merges nothing, but the site's
//!   overlay can hold credentials too, in a module's settings or a repository's URL. So the AI
//!   process is given an overlay of its own, and one that holds another process's section is refused.
//! - **The GUI's key.** ace3 signs a session cookie with a key, which the AI container replaces with a
//!   sentinel. An ace4 session is a row, so there is no key to hold: the equivalent is the role that
//!   can't read the row. The AI listener doesn't read a cookie either (`ace_api::AiWeb`).
//! - **The node-to-node key.** ace3's `api.api_key` is what nodes call each other with. Here it is the
//!   lease API's tokens: a pool's, and the admin token that replays a task.
//! - **The allow-list.** ace3 walks its configuration for a secret written as a literal that no
//!   enabled backend declares, and permits a reference it can't decrypt. An ace4 overlay names where
//!   a secret comes from, never its value, so the walk is over `secrets:`: a source this process can
//!   read, an environment variable that is set or a file that is there, has to be one an enabled
//!   backend lists. A source it can't read is permitted, as ace3's encrypted reference is.
//! - **The limiter's store.** ace3's sweep leaves out `redis.password`, which the container needs for
//!   its rate limiter. ace4's limiter is in Postgres, under the same role as everything else, so there
//!   is nothing to leave out.

use std::collections::{BTreeMap, BTreeSet};

use ace_sdk::overlay::{Overlay, SecretSource};
use ace_service::ai::role::RolePrivileges;
use serde_json::Value;

/// The email archive's key (`ace_core::email_archive::ArchiveConfig`).
pub const ENCRYPTION_KEY: &str = "ACE4_ENCRYPTION_KEY";
/// The lease API's tokens and a main API key, by variable: `ACE4_POOL_TOKEN_<POOL>` too
/// ([`LEASE_TOKEN_PREFIX`]).
pub const INFRA_SECRETS: &[&str] = &["ACE4_ADMIN_TOKEN", "ACE4_POOL_TOKEN", "ACE4_API_KEY"];
pub const LEASE_TOKEN_PREFIX: &str = "ACE4_POOL_TOKEN_";
/// The bucket's credential.
pub const BUCKET_CREDENTIALS: &[&str] = &["ACE4_BUCKET_ACCESS_KEY", "ACE4_BUCKET_SECRET_KEY"];
/// The sections `ace serve-ai` reads: the API's own, where its backends' secrets come from, and the
/// site's dispositions, which the export's `disposition_class` follows.
pub const OWN_SECTIONS: &[&str] = &[
    "ai_api",
    "secrets",
    "dispositions",
    "disposition_classification",
];
/// Where GUI sessions are kept.
pub const SESSIONS: &str = "service.sessions";
/// The schema of the email archive.
pub const ARCHIVE_SCHEMA: &str = "email_archive";

/// The process's environment: each variable that is set, with its value.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    variables: BTreeMap<String, String>,
}

impl Environment {
    /// This process's. A variable whose name or value isn't text is kept by its name, with no value.
    pub fn of_process() -> Environment {
        Environment {
            variables: std::env::vars_os()
                .map(|(name, value)| {
                    (
                        name.to_string_lossy().into_owned(),
                        value.into_string().unwrap_or_default(),
                    )
                })
                .collect(),
        }
    }

    pub fn of(variables: &[(&str, &str)]) -> Environment {
        Environment {
            variables: variables
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    /// The variable's value, when it is set.
    pub fn get(&self, name: &str) -> Option<String> {
        self.variables.get(name).cloned()
    }

    /// Whether the variable is there at all, empty or not.
    pub fn holds(&self, name: &str) -> bool {
        self.variables.contains_key(name)
    }

    fn names(&self) -> impl Iterator<Item = &str> {
        self.variables.keys().map(String::as_str)
    }
}

/// ace3's `check_no_encryption_capability`.
pub fn check_no_encryption_capability(
    env: &Environment,
    role: &RolePrivileges,
    failures: &mut Vec<String>,
) {
    if env.holds(ENCRYPTION_KEY) {
        failures.push(format!(
            "{ENCRYPTION_KEY} is set in the environment; the AI API's process must not hold the \
             email archive's key (remove it from the service's environment)"
        ));
    }
    let readable = role.reads_in(ARCHIVE_SCHEMA);
    if !readable.is_empty() {
        failures.push(format!(
            "the database role {} can read the email archive ({}); the AI API's process must not be \
             able to read archived email",
            role.user,
            readable.join(", ")
        ));
    }
}

/// ace3's `check_local_overlay_skipped`: the overlay holds the process's own sections and no other.
pub fn check_overlay_is_its_own(sections: &BTreeMap<String, Value>, failures: &mut Vec<String>) {
    let others: Vec<&str> = sections
        .keys()
        .map(String::as_str)
        .filter(|section| !OWN_SECTIONS.contains(section))
        .collect();
    if !others.is_empty() {
        failures.push(format!(
            "the overlay holds sections that aren't the AI API's: {}; without an overlay of its own \
             the site's configuration (which may hold live credentials) reaches this process. It \
             takes only {}",
            others.join(", "),
            OWN_SECTIONS.join(", ")
        ));
    }
}

/// ace3's `check_infra_secrets_neutralized`: the node-to-node key and the GUI's.
pub fn check_infra_secrets(env: &Environment, role: &RolePrivileges, failures: &mut Vec<String>) {
    let held: Vec<&str> = env
        .names()
        .filter(|name| INFRA_SECRETS.contains(name) || name.starts_with(LEASE_TOKEN_PREFIX))
        .collect();
    if !held.is_empty() {
        failures.push(format!(
            "{} set in the environment; the AI API's process must not hold a pool's token, the admin \
             token or a key to the main API (remove them from the service's environment)",
            held.join(", ")
        ));
    }
    if role.holds(SESSIONS, "SELECT") {
        failures.push(format!(
            "the database role {} can read {SESSIONS}; the AI API authenticates API keys only, and \
             must not be able to read a GUI session",
            role.user
        ));
    }
}

/// The bucket's credential: the API serves no file, so it holds no way to read or write one.
pub fn check_no_bucket_credential(env: &Environment, failures: &mut Vec<String>) {
    let held: Vec<&str> = BUCKET_CREDENTIALS
        .iter()
        .copied()
        .filter(|name| env.holds(name))
        .collect();
    if !held.is_empty() {
        failures.push(format!(
            "{} set in the environment; the AI API's process reads no file and must not hold the \
             bucket's credential",
            held.join(", ")
        ));
    }
}

/// The database role can do what migration 0064 grants, no more and no less.
pub fn check_role(role: &RolePrivileges, failures: &mut Vec<String>) {
    let beyond = role.beyond();
    if !beyond.is_empty() {
        failures.push(format!(
            "the database role {} can do more than the AI API does: {}; connect as a member of {} \
             and nothing else",
            role.user,
            summary(&beyond),
            ace_service::ai::role::ROLE
        ));
    }
    let missing = role.missing();
    if !missing.is_empty() {
        failures.push(format!(
            "the database role {} lacks what the AI API needs: {}; it has to be a member of {}",
            role.user,
            summary(&missing),
            ace_service::ai::role::ROLE
        ));
    }
}

/// The first few of `items`, and how many more.
fn summary(items: &[String]) -> String {
    const SHOWN: usize = 12;
    let mut text = items
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > SHOWN {
        text.push_str(&format!(", and {} more", items.len() - SHOWN));
    }
    text
}

/// The secrets the enabled backends list: what the process may hold. None when the API is off.
pub fn declared_secrets(overlay: &Overlay) -> Vec<String> {
    let section = &overlay.ai_api;
    if !section.enabled {
        return Vec::new();
    }
    let declared: BTreeSet<&String> = section
        .backends
        .values()
        .filter(|backend| backend.enabled)
        .flat_map(|backend| &backend.secrets)
        .collect();
    declared.into_iter().cloned().collect()
}

/// Whether this process can read the secret at `source`: a variable that is set to something, or a
/// file that is there and can be opened.
fn readable(source: &SecretSource, env: &Environment) -> bool {
    match source {
        SecretSource::Env(variable) => env.get(variable).is_some_and(|value| !value.is_empty()),
        SecretSource::File(path) => std::fs::File::open(path)
            .and_then(|file| file.metadata())
            .is_ok_and(|found| found.is_file() && found.len() > 0),
    }
}

/// ace3's `check_secret_literal_allowlist`: every secret the process can read is one an enabled
/// backend lists. The failure names the secrets, never a value.
pub fn check_secret_allowlist(
    overlay: &Overlay,
    declared: &[String],
    env: &Environment,
    failures: &mut Vec<String>,
) {
    let offenders: Vec<&str> = overlay
        .secrets
        .iter()
        .filter(|(name, source)| !declared.contains(name) && readable(source, env))
        .map(|(name, _)| name.as_str())
        .collect();
    if !offenders.is_empty() {
        failures.push(format!(
            "credential(s) present that no enabled AI query backend declares: {}. The AI API's \
             process may hold only the read-only credentials its backends own; take them out of its \
             environment, or out of its overlay's secrets",
            offenders.join(", ")
        ));
    }
}

/// Whether a setting's name reads as a credential's: ace3's `SECRETISH_FIELD_NAME`.
fn secretish(name: &str) -> bool {
    ["password", "token", "secret", "secret_key", "api_key"]
        .iter()
        .any(|ending| name.ends_with(ending))
}

/// ace3's `advisory_plaintext_sweep`: the settings whose name reads as a credential's and whose value
/// is text written in the overlay, by path. Not fatal: a name is a guess. A backend's credential
/// belongs in `secrets:`, as `env:` or `file:`, which is never flagged.
pub fn advisory_sweep(sections: &BTreeMap<String, Value>) -> Vec<String> {
    fn walk(value: &Value, path: &str, name: &str, found: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    let path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    walk(value, &path, key, found);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{index}]"), name, found);
                }
            }
            Value::String(text)
                if secretish(name)
                    && !text.is_empty()
                    && !text.starts_with("file:")
                    && !text.starts_with("env:") =>
            {
                found.push(path.to_owned());
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    for (section, value) in sections {
        // `secrets:` holds sources, which the parse has already held to `env:` and `file:`
        if section != "secrets" {
            walk(value, section, section, &mut found);
        }
    }
    found
}

/// What `ace serve` asks of its own overlay: no `ai_api` section. It doesn't serve the API, so a
/// section there would be a setting that quietly did nothing, and its backends' secrets would sit in
/// the process that holds everything else.
pub fn not_ace_serve_s(overlay: &Overlay) -> Result<(), String> {
    if overlay.ai_api == ace_sdk::overlay::AiApiSection::default() {
        return Ok(());
    }
    Err(
        "the overlay has an ai_api section: `ace serve` doesn't serve the AI investigation API. \
         `ace serve-ai` does, from an overlay of its own (ai_api, secrets and the dispositions): move \
         the section there"
            .to_owned(),
    )
}

/// What the process holds, read once when it starts.
#[derive(Debug, Clone, Default)]
pub struct Holdings {
    pub env: Environment,
    /// The overlay's sections as its file writes them (`Overlay::sections`).
    pub sections: BTreeMap<String, Value>,
    pub role: RolePrivileges,
}

/// What a start that passed found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passed {
    /// The secrets the enabled backends list.
    pub declared: Vec<String>,
    /// [`advisory_sweep`]'s paths, which the caller logs.
    pub warnings: Vec<String>,
}

/// ace3's `run_startup_checks`: every check, and one error holding every failure. `backends` is what
/// building the enabled backends gave (`crate::ai::surface`): its error is ace3's
/// `check_backend_credentials` failing.
pub fn run(
    holdings: &Holdings,
    overlay: &Overlay,
    backends: Result<(), String>,
) -> Result<Passed, String> {
    let mut failures = Vec::new();
    check_no_encryption_capability(&holdings.env, &holdings.role, &mut failures);
    check_overlay_is_its_own(&holdings.sections, &mut failures);
    check_infra_secrets(&holdings.env, &holdings.role, &mut failures);
    check_no_bucket_credential(&holdings.env, &mut failures);
    check_role(&holdings.role, &mut failures);
    if let Err(error) = backends {
        failures.push(format!("the overlay's ai_api section: {error}"));
    }
    let declared = declared_secrets(overlay);
    check_secret_allowlist(overlay, &declared, &holdings.env, &mut failures);
    if !failures.is_empty() {
        return Err(format!(
            "AI API custody checks failed, refusing to start:\n  - {}",
            failures.join("\n  - ")
        ));
    }
    Ok(Passed {
        declared,
        warnings: advisory_sweep(&holdings.sections),
    })
}

#[cfg(test)]
mod tests;
