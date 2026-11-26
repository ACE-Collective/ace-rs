//! The overlay's `alert_automation:` section (PLAN.md 7.22): the rules that act on an alert by
//! themselves when their trigger fires, ace3's `alert_automation_rule_<name>` blocks and its
//! `service_alert_automation` settings. `ace_service`'s `alert_automation` loads and runs them.
//!
//! ```yaml
//! alert_automation:
//!   max_action_attempts: 5
//!   rules:
//!     confirmed_removal:
//!       enabled: true
//!       mode: dry_run
//!       trigger:
//!         type: external_remediation_confirmed
//!         probe: some_probe
//!         max_age_hours: 120
//!       actions:
//!         - type: disposition
//!           disposition: DELIVERY
//!           comment: "{probe} confirmed removal of {observable} at {event_time}; ACE removal queued as a backstop"
//!         - type: remediate
//!           targets: same_message
//! ```
//!
//! A rule is named by its key, which every run records, so renaming a rule makes it act again on the
//! alerts it already acted on, as ace3's `name` does. A rule is off and in `dry_run` unless it says
//! otherwise. Every level refuses a key it doesn't know, the trigger's and each action's included, and
//! a `type` this build doesn't have, so a mistake stops the process that reads the overlay with its
//! path, where ace3 refuses a trigger's or an action's block only when its service loads the rule.
//! What needs the running server to check, the probe, the disposition and the comments' fields, is
//! checked when `ace serve` starts: a rule that fails is logged at ERROR and doesn't run, and the
//! others do, as in ace3.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The overlay's `alert_automation:` section.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AlertAutomationSection {
    /// How many times a failing action is tried before it is marked failed, ace3's
    /// `service_alert_automation.max_action_attempts`: 5 when left out.
    pub max_action_attempts: Option<u32>,
    /// How many alerts a sweep reads at a time, ace3's `batch_size`: 100 when left out.
    pub batch_size: Option<u32>,
    /// The rules, by name.
    pub rules: BTreeMap<String, RuleSection>,
}

/// One rule, ace3's `AlertAutomationRuleConfig`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSection {
    /// Whether the sweep runs the rule: false when left out.
    #[serde(default)]
    pub enabled: bool,
    /// `dry_run` records what each action would do and changes nothing; `enforce` does it.
    #[serde(default)]
    pub mode: Mode,
    /// What finds the alerts the rule applies to.
    pub trigger: TriggerSection,
    /// What the rule does to each alert, in this order.
    pub actions: Vec<ActionSection>,
}

/// A rule's mode, which each run records: a rule acts at most once per alert and mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    DryRun,
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::DryRun => "dry_run",
            Mode::Enforce => "enforce",
        }
    }

    pub fn parse(text: &str) -> Option<Mode> {
        [Mode::DryRun, Mode::Enforce]
            .into_iter()
            .find(|mode| mode.as_str() == text)
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rule's trigger, by its `type`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TriggerSection {
    /// An alert one of whose remediation checks by `probe` is CONFIRMED and ended within
    /// `max_age_hours` (120 when left out).
    ExternalRemediationConfirmed {
        probe: String,
        max_age_hours: Option<u32>,
    },
}

impl TriggerSection {
    pub fn type_name(&self) -> &'static str {
        match self {
            TriggerSection::ExternalRemediationConfirmed { .. } => "external_remediation_confirmed",
        }
    }
}

/// One of a rule's actions, by its `type`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionSection {
    /// Sets the alert's disposition, with a comment, a template of the trigger's fields.
    Disposition {
        disposition: String,
        comment: Option<String>,
    },
    /// Queues ACE's own removal of the observables it targets.
    Remediate { targets: Targets },
    /// Records a comment, a template of the trigger's fields.
    Comment { comment: String },
}

impl ActionSection {
    /// The action's `type`, which a run records for each of its actions.
    pub fn type_name(&self) -> &'static str {
        match self {
            ActionSection::Disposition { .. } => "disposition",
            ActionSection::Remediate { .. } => "remediate",
            ActionSection::Comment { .. } => "comment",
        }
    }
}

/// What the `remediate` action removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Targets {
    /// The observables the trigger's evidence names, as they appear in the alert.
    Evidence,
    /// Every `email_delivery` in the alert whose message-id is a confirmed delivery's.
    SameMessage,
}

impl Targets {
    pub fn as_str(self) -> &'static str {
        match self {
            Targets::Evidence => "evidence",
            Targets::SameMessage => "same_message",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::Overlay;

    fn section(yaml: &str) -> Result<AlertAutomationSection, String> {
        Overlay::from_yaml(yaml)
            .map(|overlay| overlay.alert_automation)
            .map_err(|e| e.to_string())
    }

    const RULE: &str = "
alert_automation:
  rules:
    confirmed_removal:
      enabled: true
      mode: enforce
      trigger:
        type: external_remediation_confirmed
        probe: some_probe
        max_age_hours: 120
      actions:
        - type: disposition
          disposition: DELIVERY
          comment: '{probe} confirmed removal'
        - type: remediate
          targets: same_message
        - type: comment
          comment: 'rule {rule}'
";

    /// ace3's rule block, as a site writes it.
    #[test]
    fn a_rule_reads_with_its_trigger_and_actions() {
        let section = section(RULE).expect("reads");
        let rule = &section.rules["confirmed_removal"];
        assert!(rule.enabled);
        assert_eq!(rule.mode, Mode::Enforce);
        assert_eq!(
            rule.trigger,
            TriggerSection::ExternalRemediationConfirmed {
                probe: "some_probe".to_owned(),
                max_age_hours: Some(120),
            }
        );
        assert_eq!(
            rule.actions,
            [
                ActionSection::Disposition {
                    disposition: "DELIVERY".to_owned(),
                    comment: Some("{probe} confirmed removal".to_owned()),
                },
                ActionSection::Remediate {
                    targets: Targets::SameMessage,
                },
                ActionSection::Comment {
                    comment: "rule {rule}".to_owned(),
                },
            ]
        );
        assert_eq!(
            (section.max_action_attempts, section.batch_size),
            (None, None)
        );
    }

    /// ace3's `test_a_rule_defaults_to_disabled_and_dry_run`.
    #[test]
    fn a_rule_is_off_and_in_dry_run_unless_it_says_otherwise() {
        let section = section(
            "
alert_automation:
  rules:
    quiet:
      trigger: {type: external_remediation_confirmed, probe: p}
      actions: [{type: comment, comment: hi}]
",
        )
        .expect("reads");
        let rule = &section.rules["quiet"];
        assert_eq!((rule.enabled, rule.mode), (false, Mode::DryRun));
    }

    /// ace3's `test_a_rule_rejects_an_unknown_key` and the parse half of its
    /// `test_a_trigger_or_action_block_that_does_not_validate_fails_the_rule`: an unknown key at any
    /// level, an unknown type and an unknown `targets` stop the overlay with their path, and so does a
    /// rule named twice (ace3's `test_the_configuration_rejects_two_rules_with_one_name`).
    #[test]
    fn a_mistake_in_a_rule_refuses_the_overlay_with_its_path() {
        let base = RULE.replace("        max_age_hours: 120\n", "");
        for (from, to, says) in [
            (
                "      enabled: true",
                "      enabled: true\n      extra_key: 1",
                "extra_key",
            ),
            (
                "        probe: some_probe",
                "        probe: some_probe\n        extra_key: 1",
                "extra_key",
            ),
            (
                "          disposition: DELIVERY",
                "          disposition: DELIVERY\n          extra_key: 1",
                "extra_key",
            ),
            ("targets: same_message", "targets: everything", "everything"),
            ("type: comment", "type: no_such_action", "no_such_action"),
            (
                "type: external_remediation_confirmed",
                "type: no_such_trigger",
                "no_such_trigger",
            ),
            ("mode: enforce", "mode: sometimes", "sometimes"),
            (
                "    confirmed_removal:",
                "    other: {trigger: {type: external_remediation_confirmed, probe: p}, actions: []}\n    other:",
                "duplicate",
            ),
        ] {
            let yaml = base.replace(from, to);
            assert_ne!(yaml, base, "{from}");
            let error = section(&yaml).expect_err(to);
            assert!(error.contains(says), "{to}: {error}");
            if says != "duplicate" {
                assert!(error.contains("alert_automation.rules"), "{to}: {error}");
            }
        }
    }

    #[test]
    fn a_mode_reads_back_from_its_name() {
        for mode in [Mode::DryRun, Mode::Enforce] {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(Mode::parse("sometimes"), None);
    }
}
