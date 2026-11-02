//! Eligibility: whether a module may run on an observable.
//!
//! A module is eligible for an observable when it takes the observable's type (or a type that
//! type extends), the root's analysis mode runs it, none of the observable's directives keeps
//! it off and the observable doesn't exclude it, and every module it depends on has a result
//! for the observable. The inputs, dependencies and skip directives come from the module's
//! manifest; the mode's modules from `Modes`.
//!
//! A dependency without a result yet makes a module wait, never fail: if the dependency's task
//! is cancelled and later runs, its result makes the module eligible then (ace3 #846).

use std::collections::{BTreeMap, BTreeSet};

use ace_results::ObservableKind;
use ace_sdk::Manifest;

/// The modules the core knows, by their key: the module's name, and later a named instance's.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    modules: BTreeMap<String, Manifest>,
}

impl Catalog {
    pub fn new(manifests: impl IntoIterator<Item = Manifest>) -> Catalog {
        Catalog {
            modules: manifests
                .into_iter()
                .map(|m| (m.name.to_owned(), m))
                .collect(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&Manifest> {
        self.modules.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Manifest)> {
        self.modules.iter().map(|(k, m)| (k.as_str(), m))
    }

    pub fn keys(&self) -> BTreeSet<&str> {
        self.modules.keys().map(String::as_str).collect()
    }
}

/// What eligibility reads about an observable.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub kind: ObservableKind,
    pub directives: &'a [String],
    pub exclude_modules: &'a [String],
}

/// Why a module isn't eligible for an observable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ineligible {
    /// The module doesn't take the observable's type.
    NotAnInput,
    /// The root's analysis mode doesn't run the module.
    NotInMode,
    /// A directive keeps the module off, such as `no_scan` or `exclude_all`.
    Directive(String),
    /// The observable excludes the module.
    Excluded,
    /// A module this one depends on has no result for the observable yet.
    WaitingFor(String),
}

/// Whether module `key`, with `manifest`, may run on an observable with `facts`, in a mode
/// that runs `mode_modules`, given the modules that have results for the observable.
pub fn check(
    key: &str,
    manifest: &Manifest,
    facts: Facts<'_>,
    mode_modules: &BTreeSet<&str>,
    results: &BTreeSet<&str>,
) -> Result<(), Ineligible> {
    if !manifest.accepts(facts.kind) {
        return Err(Ineligible::NotAnInput);
    }
    if !mode_modules.contains(key) {
        return Err(Ineligible::NotInMode);
    }
    if let Some(directive) = manifest.skipped_by(facts.directives) {
        return Err(Ineligible::Directive(directive.to_owned()));
    }
    if facts.exclude_modules.iter().any(|m| m == key) {
        return Err(Ineligible::Excluded);
    }
    if let Some(waiting) = manifest
        .depends_on
        .iter()
        .find(|dependency| !results.contains(**dependency))
    {
        return Err(Ineligible::WaitingFor((*waiting).to_owned()));
    }
    Ok(())
}
