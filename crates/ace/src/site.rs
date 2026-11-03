//! The modules this binary links, and the site overlay over them (PLAN.md 2.23), which `ace
//! serve` and `ace task replay` read from the YAML file at `ACE4_OVERLAY`. With no overlay,
//! every module runs as itself on its defaults.

use ace_pool::modules::Registry;
use ace_sdk::{Component, Overlay};
use anyhow::{Context, Result};

/// The five modules ported in phase 1.
pub fn registry() -> Registry {
    Registry::new()
        .parser::<ace_mod_email::EmailAnalyzer>()
        .lookup::<ace_mod_rdap::RdapAnalyzer>()
        .parser::<ace_mod_archive::ArchiveAnalyzer>()
        .parser::<ace_mod_yara::YaraScanner>()
        .lookup::<ace_mod_splunk::SplunkAnalyzer>()
}

/// The overlay at `ACE4_OVERLAY`, or none.
pub fn overlay() -> Result<Overlay> {
    match std::env::var_os("ACE4_OVERLAY") {
        Some(path) => Ok(Overlay::read(path.as_ref())?),
        None => Ok(Overlay::default()),
    }
}

/// The components the overlay makes of the registry's modules.
pub fn components(registry: &Registry, overlay: &Overlay) -> Result<Vec<Component>> {
    overlay
        .components(&registry.manifests())
        .context("loading the site overlay")
}
