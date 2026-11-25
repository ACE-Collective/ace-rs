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
//!     # ace3's `rules_config_path`: a file of rules, `rules:` at its top, which the core reads when it
//!     # starts and again whenever its contents change, as ace3 watches its file
//!     rules_file: /signatures/analyst_data/observable_modifier_rules.yaml
//!     # rules written here, which come before the file's
//!     rules:
//!       - name: suspicious html
//!         uuid: 7d8ba9a0-0b6e-4d47-9e4a-2f0d6d5a3c11
//!         conditions: {observable_types: [file], file_name_pattern: '\.html$'}
//!         actions: {add_tags: [html], add_detection_points: ["an html file"]}
//! ```
//!
//! Each level refuses keys it doesn't know, as the rest of the overlay does, except a rule's: each rule
//! is read on its own (`ModifierSection::parsed`), and the core compiles them
//! (`ace_core::hooks::rules::Rules::compile`), so one ace3 would log and skip (no uuid, an unknown phase,
//! key or scope, a pattern that doesn't compile) is logged at ERROR and skipped, and the others run, as
//! in ace3. A module is named as ace-rs names it, by its key (`archive`, `email_analyzer`), where ace3's
//! rules name a Python path (`saq.modules.archive:ArchiveAnalyzer`).

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

/// ace3's observable modifier rules: written here, or in a file, or both.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModifierSection {
    /// Each rule as it's written, read into a `ModifierRule` on its own (`parsed`), so one that doesn't
    /// read is skipped rather than refusing the overlay.
    pub rules: Vec<serde_norway::Value>,
    /// ace3's `rules_config_path`: a YAML file whose `rules:` follow these.
    pub rules_file: Option<String>,
}

impl ModifierSection {
    /// Each rule read as a `ModifierRule`, or why it doesn't read, with the path of the key at fault.
    pub fn parsed(&self) -> Vec<Result<ModifierRule, String>> {
        self.rules.iter().map(parse_rule).collect()
    }
}

/// The most bytes a rules file may hold.
pub const MAX_RULES_FILE_BYTES: u64 = 4 << 20;

/// One rule as it's written, read as a `ModifierRule`, or why not.
pub fn parse_rule(value: &serde_norway::Value) -> Result<ModifierRule, String> {
    serde_path_to_error::deserialize(value.clone()).map_err(|e| {
        let at = e.path().to_string();
        if at.is_empty() || at == "." {
            e.inner().to_string()
        } else {
            format!("{at}: {}", e.inner())
        }
    })
}

/// A rules file's text as its rules, each as it's written: what is under `rules:` at its top. Other
/// top-level keys are ignored, as ace3 reads only `rules`; a file with none has no rules.
pub fn rules_of_file(text: &str) -> Result<Vec<serde_norway::Value>, String> {
    let doc: serde_norway::Value =
        serde_norway::from_str(text).map_err(|e| format!("not YAML: {e}"))?;
    match doc.get("rules") {
        None | Some(serde_norway::Value::Null) => Ok(Vec::new()),
        Some(serde_norway::Value::Sequence(rules)) => Ok(rules.clone()),
        Some(_) => Err("`rules` isn't a list".to_owned()),
    }
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
