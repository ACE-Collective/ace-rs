//! A pool's secrets (PLAN.md 2.24): a process resolves the secrets its own modules' manifests
//! declare and no others, wherever the site overlay says each one comes from. ace3 resolved
//! every `env:` reference in its whole configuration in every process (#1009), so a container
//! needed the variables of services it never ran.
//!
//! A declared secret that isn't set is a warning, not a failed startup: a module may need only
//! one of the secrets it declares, as the Splunk module needs a password or a token, and a task
//! that needs a missing one fails with `MissingSecret`.

use std::collections::BTreeMap;

use ace_sdk::{Manifest, Overlay, Secret, SecretSource, Secrets};

/// Resolves the secrets `manifests` declare from the overlay's sources, reading environment
/// variables through `env`, and logs which it resolved. Nothing else in the overlay is read.
pub fn resolve(
    pool: &str,
    manifests: &[Manifest],
    overlay: &Overlay,
    env: &dyn Fn(&str) -> Option<String>,
) -> Secrets {
    let declared: std::collections::BTreeSet<&str> = manifests
        .iter()
        .flat_map(|m| m.secrets.iter().copied())
        .collect();
    let mut secrets = Secrets::new();
    let mut unset: BTreeMap<&str, String> = BTreeMap::new();
    for name in declared {
        let Some(source) = overlay.secrets.get(name) else {
            unset.insert(name, "the overlay names no source".to_owned());
            continue;
        };
        match read(source, env) {
            Ok(value) => secrets = secrets.with(name, Secret::new(value)),
            Err(why) => {
                unset.insert(name, format!("{source}: {why}"));
            }
        }
    }
    tracing::info!(pool, secrets = ?secrets.names(), "resolved the pool's secrets");
    for (name, why) in unset {
        tracing::warn!(pool, secret = name, "a declared secret isn't set: {why}");
    }
    secrets
}

/// The process's own environment, for `resolve`.
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn read(source: &SecretSource, env: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    match source {
        SecretSource::Env(variable) => env(variable).ok_or_else(|| "not set".to_owned()),
        SecretSource::File(path) => std::fs::read_to_string(path)
            .map(|text| {
                let text = text.strip_suffix('\n').unwrap_or(&text);
                text.strip_suffix('\r').unwrap_or(text).to_owned()
            })
            .map_err(|e| e.to_string()),
    }
}
