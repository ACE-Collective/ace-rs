//! Eligibility: whether a module may run on an observable.
//!
//! A component, a module or a named instance of one, is eligible for an observable when it
//! takes the observable's type (or a type that type extends), the root's analysis mode runs it (or,
//! when an observable modifier rule limited the observable's analysis, the limit names it),
//! none of the observable's directives keeps it off, the observable has every directive the module
//! requires and doesn't exclude it, and every module it depends on has a result for the
//! observable, if the root's mode runs that module and the binary has it. The inputs come from the
//! component (the manifest's, or an instance's narrower list), the dependencies and skip directives
//! from the module's manifest, and the mode's modules from `Modes`.
//!
//! Before any of that, an observable the site's global exclusions name (`ace_sdk::exclusions`,
//! ace3's `observable_exclusions`) is eligible for nothing: the orchestrator asks
//! `Exclusions::excludes` first and queues no task, not even the type step, as ace3's executor drops
//! the work item before it picks a module (`_process_observable_exclusions`).
//!
//! A dependency without a result yet makes a module wait, never fail: if the dependency's task
//! is cancelled and later runs, its result makes the module eligible then (ace3 #846).

use std::collections::{BTreeMap, BTreeSet};

use ace_results::ObservableKind;
use ace_sdk::lists::ListSpec;
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

    /// The analyst-edited lists the catalog's modules read (PLAN.md 5.14), by name. Two modules
    /// that read one list must declare it alike; the first module's spec is kept when they don't.
    pub fn lists(&self) -> BTreeMap<&'static str, ListSpec> {
        let mut lists: BTreeMap<&'static str, ListSpec> = BTreeMap::new();
        for component in self.components.values() {
            for spec in component.manifest.lists {
                match lists.get(spec.name) {
                    Some(kept) if kept != spec => tracing::error!(
                        list = spec.name,
                        module = component.manifest.name,
                        "a module declares a list another declares differently; the first is kept"
                    ),
                    Some(_) => {}
                    None => {
                        lists.insert(spec.name, *spec);
                    }
                }
            }
        }
        lists
    }
}

/// What eligibility reads about an observable.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub kind: ObservableKind,
    pub directives: &'a [String],
    pub exclude_modules: &'a [String],
    /// When not empty, the only modules that may analyze it, mode or not, as ace3's
    /// `limited_analysis`, which an observable modifier rule sets.
    pub limit_modules: &'a [String],
}

/// Why a module isn't eligible for an observable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ineligible {
    /// The module doesn't take the observable's type.
    NotAnInput,
    /// The root's analysis mode doesn't run the module.
    NotInMode,
    /// The observable's analysis is limited to other modules.
    NotInLimit,
    /// A directive keeps the module off, such as `no_scan` or `exclude_all`.
    Directive(String),
    /// The observable lacks a directive the module requires, such as `original_email`.
    MissingDirective(String),
    /// The observable excludes the module.
    Excluded,
    /// A module this one depends on, which the root's mode runs, has no result for the observable
    /// yet.
    WaitingFor(String),
}

/// Whether `component` may run on an observable with `facts`, in a mode that runs
/// `mode_modules` (those of the mode the catalog has), given the components that have results for the observable.
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
    // ace3 takes the limited modules in place of the mode's
    if !facts.limit_modules.is_empty() {
        if !facts.limit_modules.iter().any(|m| m == key) {
            return Err(Ineligible::NotInLimit);
        }
    } else if !mode_modules.contains(key) {
        return Err(Ineligible::NotInMode);
    }
    if let Some(directive) = manifest.skipped_by(facts.directives) {
        return Err(Ineligible::Directive(directive.to_owned()));
    }
    if let Some(directive) = manifest.missing_directive_for(facts.kind, facts.directives) {
        return Err(Ineligible::MissingDirective(directive.to_owned()));
    }
    if facts.exclude_modules.iter().any(|m| m == key) {
        return Err(Ineligible::Excluded);
    }
    if let Some(waiting) = manifest
        .depends_on
        .iter()
        // a dependency the root's mode doesn't run, or the binary doesn't have, never has a
        // result, and doesn't hold the module back, as ace3's YARA-only mode runs its module
        // without file_type
        .find(|dependency| mode_modules.contains(**dependency) && !results.contains(**dependency))
    {
        return Err(Ineligible::WaitingFor((*waiting).to_owned()));
    }
    Ok(())
}
