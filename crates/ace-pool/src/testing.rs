//! The test pool's modules (feature `test-pools`): ported modules, for tests that run real
//! modules through a pool.

use ace_sdk::Secrets;
use serde_json::Value;

use crate::modules::{Entry, Modules, SetupError};

/// The modules `test-pool` runs, each with its block from `settings`, an object keyed by
/// module name.
pub fn modules(settings: &Value) -> Result<Modules, SetupError> {
    let secrets = Secrets::new();
    let block = |name: &str| settings.get(name);
    Ok(Modules::new()
        .with_parser(Entry::<ace_mod_archive::ArchiveAnalyzer>::parser(
            block("archive"),
            &secrets,
        )?)
        .with_parser(Entry::<ace_mod_email::EmailAnalyzer>::parser(
            block("email_analyzer"),
            &secrets,
        )?))
}
