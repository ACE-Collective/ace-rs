//! Eligibility: whether a module may run on an observable.
//!
//! A component, a module or a named instance of one, is eligible for an observable when it
//! takes the observable's type (or a type that type extends), the root's analysis mode runs it,
//! none of the observable's directives keeps it off and the observable doesn't exclude it, and
//! every module it depends on has a result for the observable. The inputs come from the component (the manifest's, or an instance's
//! narrower list), the dependencies and skip directives from the module's manifest, and the
//! mode's modules from `Modes`.
//!
//! A dependency without a result yet makes a module wait, never fail: if the dependency's task
//! is cancelled and later runs, its result makes the module eligible then (ace3 #846).

use std::collections::{BTreeMap, BTreeSet};

use ace_results::ObservableKind;
use ace_sdk::{Component, Manifest};

/// The components the core knows, by key: each module as itself, or its named instances from
/// the site overlay (PLAN.md 2.23).
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    components: BTreeMap<String, Component>,
}

impl Catalog {
    /// Each module as itself, on its defaults: the catalog of a site with no overlay.
    pub fn new(manifests: impl IntoIterator<Item = Manifest>) -> Catalog {
        Catalog::of(manifests.into_iter().map(Component::of))
    }

    /// The components a site overlay made (`Overlay::components`).
    pub fn of(components: impl IntoIterator<Item = Component>) -> Catalog {
        Catalog {
            components: components.into_iter().map(|c| (c.key.clone(), c)).collect(),
        }
    }

    /// The manifest of the module the component `key` runs.
    pub fn get(&self, key: &str) -> Option<&Manifest> {
        self.components.get(key).map(|c| &c.manifest)
    }

    pub fn component(&self, key: &str) -> Option<&Component> {
        self.components.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Component> {
        self.components.values()
    }

    pub fn keys(&self) -> BTreeSet<&str> {
        self.components.keys().map(String::as_str).collect()
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

/// Whether `component` may run on an observable with `facts`, in a mode that runs
/// `mode_modules`, given the components that have results for the observable.
pub fn check(
    component: &Component,
    facts: Facts<'_>,
    mode_modules: &BTreeSet<&str>,
    results: &BTreeSet<&str>,
) -> Result<(), Ineligible> {
    let (key, manifest) = (component.key.as_str(), &component.manifest);
    if !component.accepts(facts.kind) {
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
