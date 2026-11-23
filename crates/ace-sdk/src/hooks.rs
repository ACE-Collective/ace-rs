//! The overlay's `hooks:` section (PLAN.md 7.6): the settings of the two modules ace3 runs over the
//! whole tree, which ace-rs runs in the core rather than on a pool (`ace_core::hooks`).
//!
//! ```yaml
//! hooks:
//!   # ace3's top-level `tags:` section, which configuration_defined_tagging reads. ace3 ships the
//!   # module disabled, so it runs only when this section is here.
//!   configuration_defined_tagging:
//!     tags: {phish: alert, suspect: warning, debug: fp}
//!   # ace3's etc/observable_modifier_rules.yaml, in its own schema. ace3 ships it enabled with no rules,
//!   # which does nothing, as no section does here.
//!   observable_modifier:
//!     rules:
//!       - name: suspicious html
//!         uuid: 7d8ba9a0-0b6e-4d47-9e4a-2f0d6d5a3c11
//!         conditions: {observable_types: [file], file_name_pattern: '\.html$'}
//!         actions: {add_tags: [html], add_detection_points: ["an html file"]}
//! ```
//!
//! Each level refuses keys it doesn't know, as the rest of the overlay does. The core compiles and checks
//! the rules when it starts (`ace_core::hooks::Hooks::from_section`), so a rule ace3 would log and skip, one
//! with no uuid, an unknown phase or scope, or a pattern that doesn't compile, stops startup here. A module
//! is named as ace-rs names it, by its key (`archive`, `email_analyzer`), where ace3's rules name a Python
//! path (`saq.modules.archive:ArchiveAnalyzer`).

use std::collections::BTreeMap;

use serde::Deserialize;

/// The overlay's `hooks:` section.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HooksSection {
    pub configuration_defined_tagging: Option<TaggingSection>,
    pub observable_modifier: Option<ModifierSection>,
}

/// ace3's `tags:` section: each tag's level. A tag whose level is `alert`, `critical` or `warning`
/// makes the root a detection when anything in it has the tag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TaggingSection {
    pub tags: BTreeMap<String, String>,
}

/// ace3's observable modifier rules file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModifierSection {
    pub rules: Vec<ModifierRule>,
}

/// When a rule runs: `pre` as each observable joins the tree, before anything analyzes it; `post` once
/// nothing else is left to run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Pre,
    #[default]
    Post,
}

/// One rule, as ace3's YAML writes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModifierRule {
    #[serde(default = "unnamed")]
    pub name: String,
    /// Required, as in ace3: a matched rule's uuid becomes a `signature_id` observable and its
    /// detections' signature.
    pub uuid: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub phase: Phase,
    #[serde(default)]
    pub conditions: RuleConditions,
    #[serde(default)]
    pub actions: RuleActions,
}

fn unnamed() -> String {
    "unnamed".to_owned()
}

fn yes() -> bool {
    true
}

/// What a rule matches. Every condition given must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuleConditions {
    pub alert_tags: Vec<String>,
    pub alert_type: Option<String>,
    pub queue: Option<String>,
    /// Observable types, a type's subtypes included.
    pub observable_types: Vec<String>,
    pub value_pattern: Option<String>,
    pub file_name_pattern: Option<String>,
    pub display_type_pattern: Option<String>,
    pub display_value_pattern: Option<String>,
    pub has_tags: Vec<String>,
    pub has_directives: Vec<String>,
    pub has_yara_meta_tags: Vec<String>,
    pub tree_conditions: Vec<TreeCondition>,
}

/// Where a tree condition looks for results, from the observable the rule is evaluating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Ancestors,
    Descendants,
    Global,
    #[serde(rename = "self")]
    This,
    Parent,
    Siblings,
}

/// A condition over the results in the tree around the observable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TreeCondition {
    /// The module whose results count, by its key; empty for any.
    pub analysis_type: String,
    pub scope: Scope,
    /// A dotted path into the result's details, each with a pattern its value must match.
    pub details_match: BTreeMap<String, String>,
    /// `type`, `value` or `file_name` of the observable the result analyzed, each with a pattern.
    pub observable_match: BTreeMap<String, String>,
    pub produces_observable: Option<ProducesObservable>,
    pub negate: bool,
    /// Exactly this many results must match; none means at least one.
    pub match_count: Option<u32>,
}

/// An observable the result added.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducesObservable {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub value: Option<String>,
}

/// What a rule does to the observable it matched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuleActions {
    pub add_directives: Vec<String>,
    pub add_tags: Vec<String>,
    pub add_detection_points: Vec<String>,
    pub exclude_analysis: Vec<String>,
    pub limit_analysis: Vec<String>,
    pub reset_analysis: Vec<String>,
    pub set_display_type: Option<String>,
    pub set_display_value: Option<String>,
    pub ignore: bool,
}
