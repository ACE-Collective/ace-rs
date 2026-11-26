//! Alert automation (PLAN.md 7.22): ace3's `saq/alert_automation/` (its `c55f15a2`), which acts on an
//! alert by itself when a rule's trigger fires. A rule is the overlay's (`ace_sdk::alert_automation`):
//! one trigger, which finds the alerts it applies to and what it found on each (its evidence), and a list
//! of actions, which run on each of those alerts in order. The first use is a confirmed external removal of
//! an email: a remediation check of a probe (PLAN.md 7.9, decision 32) confirms that another product
//! removed the email an open alert is about, and the rule sets the alert's disposition to DELIVERY and
//! queues ACE's own removal of every delivery of the message as a backstop.
//!
//! **Loading.** `AlertAutomation::load` checks each enabled rule against the server when `ace serve`
//! starts: its probe is a remediation check handler the binary has and the overlay leaves on (decision 28),
//! its disposition one of the site's an analyst may select, and its comments name only the fields its
//! trigger gives. A rule that fails is logged at ERROR with its name and doesn't run; the others do.
//!
//! **The trigger.** `external_remediation_confirmed` matches an alert with a remediation check of its
//! `probe` that ended CONFIRMED within `max_age_hours` (120) of the database's `now()`. One confirmed
//! delivery is enough. A check on a root that isn't an alert yet matches nothing until it is one, since a
//! probe's module often confirms first. The evidence is the probe and its confirmed checks, each with its
//! id, type, value and when it ended, and a comment may name `{probe}`, `{observable}` (the confirmed
//! values, comma-separated), `{event_time}` (the latest confirmation, RFC 3339 in UTC), `{rule}` and
//! `{alert_uuid}`. A template is ace3's format string without its format specs and conversions: `{{` and
//! `}}` are braces, and anything else in braces that isn't one of those names fails the rule at load.
//!
//! **The actions.** Each reports done, skipped (with why) or deferred, or fails.
//! - `disposition` sets the alert's disposition through the one writer of it (`Service::disposition_in`),
//!   as this sweep's component, with the rendered comment, once the guards and the trigger still hold under
//!   the alert's row lock. Otherwise it defers: the rule's later actions don't run, and a run none of whose
//!   actions finished is deleted, so the rule considers the alert again on a later sweep. ACE's components
//!   never own an alert (migration 0056), so the alert stays nobody's, where ace3's becomes its automation
//!   user's.
//! - `remediate` queues a `remove` of each target, attributed to this sweep's component and to nobody, as
//!   ace3 attributes it to its automation user: `targets: evidence` takes the observables the evidence
//!   names, as they are in the alert, and `targets: same_message` every `email_delivery` (or a type that
//!   extends it) in the alert whose message-id is a confirmed delivery's, including deliveries a module
//!   added since. A target is a remediator of the observable's type (`remediation`'s rule); one whose
//!   latest removal covers it (`ace_core::actions::removal_covers`) isn't queued again. An observable no
//!   remediator acts on means there is no backstop for it, which is logged at ERROR. An alert with nothing
//!   to remediate skips the action.
//! - `comment` adds its rendered text to the alert (PLAN.md 5.15) in enforce, and records it in dry_run,
//!   as the disposition's comment is added with the disposition. Both are ACE's own: a comment with no
//!   author, written by this sweep's component and shown as `ACE`, where ace3 writes them as its
//!   automation user (PLAN.md decision 71). The run's record and the step's audit row name it too.
//!
//! **The guards**, which a rule can't turn off: the alert exists, nobody owns it, and its disposition is
//! OPEN (so a frozen one, SIMULATED, is never touched). Once one of a run's actions has finished the alert
//! is in the state the run put it in, so the disposition guard no longer applies to that run; the
//! ownership guard always does, and a pending run on an alert someone owns, or on one that was deleted, is
//! left as it is and logged at INFO on each sweep. The guards are checked under the alert's row lock in
//! the transaction of each action, in both modes.
//!
//! **Runs and modes.** `analysis.alert_automation_runs` (migration 0092) holds one row per rule, alert and
//! mode, inserted in the transaction of the run's first action, so a rule acts at most once on an alert in
//! a mode: reopening the alert doesn't set it off again, and switching a rule from `dry_run` to `enforce`
//! acts on the alerts the dry run saw if they are still open and nobody's. Each action is one transaction
//! with its record on the run and its audit row, so an action and the record that it ran commit or roll
//! back together, and a sweep that is stopped or dies between them leaves nothing half done. A failed
//! action is rolled back, logged at ERROR, counted on the run in a transaction of its own, and tried again
//! on later sweeps until `max_action_attempts`, when it and the run are marked failed and the rule's later
//! actions never run. A pending run whose recorded actions are no longer the rule's (an edited rule) is
//! marked failed and logged at ERROR. In `dry_run` each action records what it would do, with the same
//! guards and checks, and changes nothing else.
//!
//! **Two sweeps at once.** ace3 claims a pending run with a version and a ten-minute lease before it
//! retries it, because its actions run outside the run's transaction. Here each action runs inside it, so
//! the claim is the run's row lock, taken with `SKIP LOCKED`: a sweep that finds the run locked leaves it to
//! the sweep that holds it, and one that finds its version moved since it read the run leaves it alone, as
//! ace3's version check does. A new run's insert waits for another sweep's uncommitted insert of the same
//! key, which is one action's transaction, and then finds the row. The scheduler runs one sweep at a time
//! across replicas anyway (`ace_app::scheduler`).
//!
//! **The sweep.** The scheduler's `alert_automation` task, every minute as ace3's `interval_seconds`, runs
//! `Service::run_alert_automation` as its component, which holds only `alert_automation:run`. For each
//! enabled rule, by name, it retries the rule's pending runs, then reads the trigger's candidates
//! `batch_size` at a time, by alert uuid, leaving out the alerts the rule has a run on in its mode and
//! those the guards would leave alone. A step's failure is logged and the sweep goes on to the next alert,
//! and a rule whose read fails is logged and the sweep goes on to the next rule, as ace3's does.
//!
//! Not here from ace3: integrations' own trigger and action types (`alert_automation.trigger_types` and
//! `action_types`), which wait for a site that needs one and an `App` extension point then; and `ace
//! alert-automation list` and `report`, since ace-rs has no such command area (PLAN.md 7.22).

use std::collections::{BTreeSet, VecDeque};

use ace_core::actions::{self as core_actions, ActionCatalog, NewRemediation};
use ace_core::db::Tx;
use ace_results::ObservableKind;
use ace_sdk::actions::{ActionKind, RemediationAction};
use ace_sdk::alert_automation::{
    ActionSection, AlertAutomationSection, Mode, RuleSection, Targets, TriggerSection,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use crate::dispositions::Dispositions;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::observables::OPEN;
use crate::permission::ALERT_AUTOMATION_RUN;
use crate::{Actor, Service, ServiceError};

/// ace3's `max_action_attempts`.
pub const DEFAULT_MAX_ACTION_ATTEMPTS: u32 = 5;
/// ace3's `batch_size`.
pub const DEFAULT_BATCH_SIZE: u32 = 100;
/// The largest `batch_size`.
pub const MAX_BATCH_SIZE: u32 = 1000;
/// ace3's `max_age_hours`.
pub const DEFAULT_MAX_AGE_HOURS: u32 = 120;
/// The longest `max_age_hours`, ten years.
pub const MAX_AGE_HOURS: u32 = 87_600;
/// The most observables one `remediate` reads from an alert; an alert with more fails the action.
pub const MAX_REMEDIATE_OBSERVABLES: i64 = 10_000;
/// The longest rule name, which `analysis.alert_automation_runs` holds.
pub const MAX_RULE_NAME: usize = 128;

const TRIGGER_FIELDS: &[&str] = &["alert_uuid", "event_time", "observable", "probe", "rule"];

/// The rules `ace serve` sweeps, as `load` checked them.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertAutomation {
    rules: Vec<Rule>,
    max_action_attempts: u32,
    batch_size: u32,
}

impl Default for AlertAutomation {
    fn default() -> Self {
        AlertAutomation {
            rules: Vec::new(),
            max_action_attempts: DEFAULT_MAX_ACTION_ATTEMPTS,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

/// One enabled rule that loaded.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub name: String,
    pub mode: Mode,
    trigger: Trigger,
    actions: Vec<Action>,
}

/// `external_remediation_confirmed`, the one trigger there is.
#[derive(Debug, Clone, PartialEq)]
struct Trigger {
    probe: String,
    max_age_hours: i32,
}

#[derive(Debug, Clone, PartialEq)]
enum Action {
    Disposition {
        disposition: String,
        comment: Option<Template>,
    },
    Remediate {
        targets: Targets,
    },
    Comment {
        comment: Template,
    },
}

impl Action {
    fn type_name(&self) -> &'static str {
        match self {
            Action::Disposition { .. } => "disposition",
            Action::Remediate { .. } => "remediate",
            Action::Comment { .. } => "comment",
        }
    }
}

impl AlertAutomation {
    /// The overlay's enabled rules, each checked against the site's dispositions and the binary's action
    /// handlers. A rule that fails is logged at ERROR and left out, and the others load, as ace3's
    /// `load_rules`. A section-wide setting out of bounds is an error, which stops `ace serve`.
    pub fn load(
        section: &AlertAutomationSection,
        dispositions: &Dispositions,
        actions: &ActionCatalog,
    ) -> Result<AlertAutomation, String> {
        let max_action_attempts = section
            .max_action_attempts
            .unwrap_or(DEFAULT_MAX_ACTION_ATTEMPTS);
        if max_action_attempts == 0 {
            return Err(
                "alert_automation.max_action_attempts: an action is tried at least once".to_owned(),
            );
        }
        let batch_size = section.batch_size.unwrap_or(DEFAULT_BATCH_SIZE);
        if !(1..=MAX_BATCH_SIZE).contains(&batch_size) {
            return Err(format!(
                "alert_automation.batch_size: a sweep reads 1 to {MAX_BATCH_SIZE} alerts at a time"
            ));
        }
        let mut rules = Vec::new();
        for (name, rule) in section.rules.iter().filter(|(_, rule)| rule.enabled) {
            match Rule::load(name, rule, dispositions, actions) {
                Ok(rule) => {
                    tracing::info!(rule = %rule.name, mode = %rule.mode, "loaded alert automation rule {}", rule.name);
                    rules.push(rule);
                }
                Err(why) => tracing::error!(
                    rule = %name,
                    "alert automation rule {name} failed to load and does not run: {why}"
                ),
            }
        }
        Ok(AlertAutomation {
            rules,
            max_action_attempts,
            batch_size,
        })
    }

    /// The rules that loaded, by name.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Rule {
    fn load(
        name: &str,
        section: &RuleSection,
        dispositions: &Dispositions,
        catalog: &ActionCatalog,
    ) -> Result<Rule, String> {
        let valid_name = !name.is_empty()
            && name.len() <= MAX_RULE_NAME
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
        if !valid_name {
            return Err(format!(
                "a rule's name is 1 to {MAX_RULE_NAME} of ASCII letters, digits, _ . and -"
            ));
        }
        let trigger = match &section.trigger {
            TriggerSection::ExternalRemediationConfirmed {
                probe,
                max_age_hours,
            } => {
                if catalog.get(ActionKind::RemediationCheck, probe).is_none() {
                    return Err(format!(
                        "trigger.probe: {probe} isn't a remediation probe of this server, or the overlay \
                         leaves it off"
                    ));
                }
                let hours = max_age_hours.unwrap_or(DEFAULT_MAX_AGE_HOURS);
                if !(1..=MAX_AGE_HOURS).contains(&hours) {
                    return Err(format!(
                        "trigger.max_age_hours: {hours} isn't 1 to {MAX_AGE_HOURS}"
                    ));
                }
                Trigger {
                    probe: probe.clone(),
                    max_age_hours: i32::try_from(hours).unwrap_or(i32::MAX),
                }
            }
        };
        if section.actions.is_empty() {
            return Err("actions: a rule has at least one action".to_owned());
        }
        let mut actions = Vec::with_capacity(section.actions.len());
        for (i, action) in section.actions.iter().enumerate() {
            let at = |why: String| format!("actions[{i}] ({}): {why}", action.type_name());
            actions.push(match action {
                ActionSection::Disposition {
                    disposition,
                    comment,
                } => {
                    match dispositions.get(disposition) {
                        None => {
                            return Err(at(format!(
                                "disposition {disposition} isn't one of this site's dispositions"
                            )));
                        }
                        Some(d) if !d.analyst_selectable => {
                            return Err(at(format!(
                                "disposition {disposition} isn't analyst_selectable; only ACE's own \
                                 subsystems set it"
                            )));
                        }
                        Some(_) => {}
                    }
                    Action::Disposition {
                        disposition: disposition.clone(),
                        comment: comment
                            .as_deref()
                            .map(Template::parse)
                            .transpose()
                            .map_err(at)?,
                    }
                }
                ActionSection::Remediate { targets } => Action::Remediate { targets: *targets },
                ActionSection::Comment { comment } => {
                    if comment.trim().is_empty() {
                        return Err(at("a comment can't be empty".to_owned()));
                    }
                    Action::Comment {
                        comment: Template::parse(comment).map_err(at)?,
                    }
                }
            });
        }
        Ok(Rule {
            name: name.to_owned(),
            mode: section.mode,
            trigger,
            actions,
        })
    }

    fn action_types(&self) -> Vec<String> {
        self.actions
            .iter()
            .map(|a| a.type_name().to_owned())
            .collect()
    }
}

/// A comment's template: ace3's `str.format_map` over the trigger's fields, without format specs.
#[derive(Debug, Clone, PartialEq)]
struct Template(Vec<Piece>);

#[derive(Debug, Clone, PartialEq)]
enum Piece {
    Text(String),
    Field(&'static str),
}

impl Template {
    /// The template, or why it isn't one: a field that isn't the trigger's, or a lone brace.
    fn parse(text: &str) -> Result<Template, String> {
        let mut pieces = Vec::new();
        let mut literal = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    literal.push('{');
                }
                '{' => {
                    let mut name = String::new();
                    loop {
                        match chars.next() {
                            Some('}') => break,
                            Some(c) => name.push(c),
                            None => return Err("the template has a { with no }".to_owned()),
                        }
                    }
                    let field = TRIGGER_FIELDS
                        .iter()
                        .find(|field| **field == name)
                        .ok_or_else(|| {
                            format!(
                                "template field {{{name}}} is not one of {}",
                                TRIGGER_FIELDS.join(", ")
                            )
                        })?;
                    if !literal.is_empty() {
                        pieces.push(Piece::Text(std::mem::take(&mut literal)));
                    }
                    pieces.push(Piece::Field(field));
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    literal.push('}');
                }
                '}' => return Err("the template has a } with no {".to_owned()),
                c => literal.push(c),
            }
        }
        if !literal.is_empty() {
            pieces.push(Piece::Text(literal));
        }
        Ok(Template(pieces))
    }

    fn render(&self, rule: &str, root: Uuid, evidence: &Evidence) -> String {
        let mut out = String::new();
        for piece in &self.0 {
            match piece {
                Piece::Text(text) => out.push_str(text),
                Piece::Field("rule") => out.push_str(rule),
                Piece::Field("alert_uuid") => out.push_str(&root.to_string()),
                Piece::Field("probe") => out.push_str(&evidence.probe),
                Piece::Field("observable") => {
                    let values: BTreeSet<&str> = evidence
                        .confirmations
                        .iter()
                        .map(|c| c.observable_value.as_str())
                        .collect();
                    out.push_str(&values.into_iter().collect::<Vec<_>>().join(", "));
                }
                Piece::Field(_) => match evidence
                    .confirmations
                    .iter()
                    .filter_map(|c| c.confirmed_at)
                    .max()
                {
                    Some(at) => {
                        out.push_str(&at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    }
                    None => out.push_str("an unknown time"),
                },
            }
        }
        out
    }
}

/// What the trigger found on an alert, which its run records and its actions are given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub probe: String,
    pub confirmations: Vec<Confirmation>,
}

/// One confirmed remediation check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Confirmation {
    pub check_id: i64,
    pub observable_type: String,
    pub observable_value: String,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// A run's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Pending,
    Done,
    Failed,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            RunStatus::Pending => "pending",
            RunStatus::Done => "done",
            RunStatus::Failed => "failed",
        }
    }

    fn parse(text: &str) -> RunStatus {
        match text {
            "done" => RunStatus::Done,
            "failed" => RunStatus::Failed,
            _ => RunStatus::Pending,
        }
    }
}

/// One action's status in a run: done and skipped are final, and so is failed, once its attempts ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Pending,
    Done,
    Skipped,
    Failed,
}

impl ActionStatus {
    fn finished(self) -> bool {
        matches!(self, ActionStatus::Done | ActionStatus::Skipped)
    }

    fn as_str(self) -> &'static str {
        match self {
            ActionStatus::Pending => "pending",
            ActionStatus::Done => "done",
            ActionStatus::Skipped => "skipped",
            ActionStatus::Failed => "failed",
        }
    }
}

/// One action's record in a run, ace3's `{type, status, attempts, detail, reason}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: ActionStatus,
    pub attempts: u32,
    pub detail: Detail,
    pub reason: Option<String>,
}

impl ActionRecord {
    fn pending(kind: &str) -> ActionRecord {
        ActionRecord {
            kind: kind.to_owned(),
            status: ActionStatus::Pending,
            attempts: 0,
            detail: Detail::default(),
            reason: None,
        }
    }
}

/// What an action did, or in dry_run would have done: the keys of ace3's `detail` its type sets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// `remediator:type:value` of each removal queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<String>>,
    /// Each target whose latest removal covers it, so none was queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered: Option<Vec<String>>,
    /// `type:value` of each observable no remediator acts on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untargeted: Option<Vec<String>>,
}

/// A run as a step's audit row records it.
#[derive(Debug, Clone, Serialize)]
struct RunRecord<'a> {
    run: i64,
    rule: &'a str,
    mode: &'static str,
    status: &'static str,
    actions: &'a [ActionRecord],
}

impl Recorded for RunRecord<'_> {}

/// What else a step's audit row says: the action it took and what it changed outside the run.
#[derive(Debug, Clone, Serialize)]
struct StepRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disposition_before: Option<&'a str>,
    #[serde(skip_serializing_if = "<[i64]>::is_empty")]
    remediations: &'a [i64],
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

impl Recorded for StepRecord<'_> {}

/// What a sweep did, for the scheduler's run row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AutomationSweep {
    /// The rules swept.
    pub rules: usize,
    /// Runs recorded on alerts no run of the rule had.
    pub runs_started: u64,
    /// Actions done or skipped.
    pub actions_finished: u64,
    /// Actions that left the alert alone because it changed since the sweep chose it.
    pub actions_deferred: u64,
    /// Actions that failed, each counted on its run.
    pub actions_failed: u64,
    /// Runs marked failed: an action out of attempts, or a rule whose actions changed.
    pub runs_failed: u64,
    /// Pending runs the guards, or another sweep, left as they were.
    pub left_alone: u64,
    /// Steps whose failure couldn't be recorded, and rules whose sweep failed, each logged at ERROR.
    pub unrecorded: u64,
    /// The first of those failures.
    pub first_error: Option<String>,
}

/// A run as a sweep read it.
#[derive(Debug, Clone)]
struct ReadRun {
    id: i64,
    version: i32,
}

/// An alert a sweep acts on, and the run it has, if any.
#[derive(Debug, Clone)]
struct Item {
    root: Uuid,
    evidence: Evidence,
    run: Option<ReadRun>,
}

/// One transaction of a sweep: an alert's next action, or the record of its failure.
#[derive(Debug, Clone)]
enum Step<'r> {
    Act {
        rule: &'r Rule,
        item: Item,
    },
    Failed {
        rule: &'r Rule,
        item: Item,
        reason: String,
    },
}

/// What a step did.
#[derive(Debug)]
enum Stepped {
    /// The action finished; `run` and `version` are the run as the step left it.
    Finished {
        action: String,
        status: ActionStatus,
        detail: Detail,
        reason: Option<String>,
        run: ReadRun,
        run_status: RunStatus,
        new: bool,
    },
    /// The action left the alert alone; `kept` says whether its run is kept.
    Deferred {
        action: String,
        reason: String,
        kept: bool,
    },
    /// The guards, or another sweep, left the alert as it was.
    LeftAlone { reason: String, pending: bool },
    /// The run's recorded actions aren't the rule's, so it was marked failed.
    Mismatched { recorded: Vec<String> },
    /// A failure was counted on the run.
    Counted {
        action: String,
        attempts: u32,
        gave_up: bool,
        new: bool,
    },
}

/// What the guards say: why the alert is left alone, or None.
fn left_alone_because(
    disposition: Option<&str>,
    owner: Option<Uuid>,
    started: bool,
) -> Option<String> {
    if let Some(owner) = owner {
        return Some(format!("user {owner} owns the alert"));
    }
    match disposition {
        Some(d) if d != OPEN && !started => Some(format!("the alert's disposition is {d}")),
        _ => None,
    }
}

/// The message-id of an `email_delivery`, `<id>|<mailbox>`, normalized and lowercased: ace3's
/// `_message_id`. None for a value with no `|`.
fn message_id(delivery: &str) -> Option<String> {
    let (id, _) = delivery.rsplit_once('|')?;
    Some(ace_sdk::email_threads::normalize_message_id(id).to_lowercase())
}

/// The observable types that are `email_delivery` or extend it, as this process knows them.
fn delivery_types() -> Vec<String> {
    ObservableKind::all()
        .iter()
        .filter(|kind| kind.is_subtype_of(ObservableKind::EmailDelivery))
        .map(|kind| kind.as_str().to_owned())
        .collect()
}

fn is_delivery(kind: &str) -> bool {
    kind.parse::<ObservableKind>()
        .is_ok_and(|kind| kind.is_subtype_of(ObservableKind::EmailDelivery))
}

impl Service {
    /// The service with the overlay's alert automation rules (`AlertAutomation::load`). None by default.
    pub fn with_alert_automation(mut self, automation: AlertAutomation) -> Self {
        self.automation = std::sync::Arc::new(automation);
        self
    }

    /// Sweeps every rule once, ace3's `AlertAutomationService.sweep`: for each, its pending runs, then the
    /// alerts its trigger finds that it has no run on. Each action is a write of its own under
    /// `alert_automation:run`, which only the scheduler's `scheduler:alert_automation` holds; a refused
    /// actor is `PermissionDenied` before anything is read. A step that fails is logged and counted, and the
    /// sweep goes on to the next alert; a rule whose read fails is logged and counted, and the sweep goes on to
    /// the next rule.
    pub async fn run_alert_automation(
        &self,
        actor: &Actor,
    ) -> Result<AutomationSweep, ServiceError> {
        let automation = self.automation.clone();
        let mut sweep = AutomationSweep {
            rules: automation.rules.len(),
            ..AutomationSweep::default()
        };
        if automation.rules.is_empty() {
            // refused all the same, so a missing grant shows before the first rule is added
            self.gate
                .read(
                    actor,
                    "run_alert_automation",
                    &ALERT_AUTOMATION_RUN,
                    &|_| Box::pin(async { Ok(()) }),
                )
                .await?;
            return Ok(sweep);
        }
        let batch = i64::from(automation.batch_size);
        for rule in &automation.rules {
            let mut pages = Pages::Pending { after: 0 };
            loop {
                let read = match pages {
                    Pages::Pending { after } => self
                        .pending_runs(actor, rule, after, batch)
                        .await
                        .map(|items| {
                            pages = match items.last() {
                                Some((id, _)) if items.len() as i64 == batch => {
                                    Pages::Pending { after: *id }
                                }
                                _ => Pages::Candidates { after: None },
                            };
                            items.into_iter().map(|(_, item)| item).collect::<Vec<_>>()
                        }),
                    Pages::Candidates { after } => self
                        .candidates(actor, rule, after, batch)
                        .await
                        .inspect(|items| {
                            pages = match items.last() {
                                Some(item) if items.len() as i64 == batch => Pages::Candidates {
                                    after: Some(item.root),
                                },
                                _ => Pages::Done,
                            };
                        }),
                    Pages::Done => break,
                };
                let items = match read {
                    Ok(items) => items,
                    Err(error @ ServiceError::PermissionDenied { .. }) => return Err(error),
                    Err(error) => {
                        // the other rules still run, and this one is swept again next time
                        tracing::error!(
                            rule = %rule.name, mode = %rule.mode,
                            "alert automation rule {} sweep failed: {error}", rule.name
                        );
                        sweep.unrecorded += 1;
                        sweep.first_error.get_or_insert_with(|| error.to_string());
                        break;
                    }
                };
                let mut steps: VecDeque<Step<'_>> = items
                    .into_iter()
                    .map(|item| Step::Act { rule, item })
                    .collect();
                while let Some(step) = steps.pop_front() {
                    let step = &step;
                    let max_attempts = automation.max_action_attempts;
                    let written = self
                        .gate
                        .write(
                            actor,
                            "run_alert_automation",
                            &ALERT_AUTOMATION_RUN,
                            &|tx| {
                                Box::pin(async move {
                                    match step {
                                        Step::Act { rule, item } => {
                                            self.act_in(tx, actor, rule, item).await
                                        }
                                        Step::Failed { rule, item, reason } => {
                                            failed_in(tx, rule, item, reason, max_attempts).await
                                        }
                                    }
                                })
                            },
                        )
                        .await;
                    if let Some(next) = next_step(&mut sweep, step, written, max_attempts)? {
                        steps.push_front(next);
                    }
                }
            }
        }
        Ok(sweep)
    }

    /// A rule's pending runs after the run `after`, in id order.
    async fn pending_runs(
        &self,
        actor: &Actor,
        rule: &Rule,
        after: i64,
        limit: i64,
    ) -> Result<Vec<(i64, Item)>, ServiceError> {
        self.gate
            .read(
                actor,
                "run_alert_automation",
                &ALERT_AUTOMATION_RUN,
                &|tx| {
                    Box::pin(async move {
                        let rows = sqlx::query!(
                            r#"SELECT id, root_id, evidence AS "evidence: Json<Evidence>", version
                           FROM analysis.alert_automation_runs
                           WHERE rule_name = $1 AND mode = $2 AND status = 'pending' AND id > $3
                           ORDER BY id LIMIT $4"#,
                            rule.name,
                            rule.mode.as_str(),
                            after,
                            limit,
                        )
                        .fetch_all(tx.conn())
                        .await?;
                        Ok(rows
                            .into_iter()
                            .map(|row| {
                                (
                                    row.id,
                                    Item {
                                        root: row.root_id,
                                        evidence: row.evidence.0,
                                        run: Some(ReadRun {
                                            id: row.id,
                                            version: row.version,
                                        }),
                                    },
                                )
                            })
                            .collect())
                    })
                },
            )
            .await
    }

    /// The trigger's candidates after the alert `after`, in uuid order, each with its evidence: open alerts
    /// nobody owns with a confirmed check of the probe, that the rule has no run on in its mode.
    async fn candidates(
        &self,
        actor: &Actor,
        rule: &Rule,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<Item>, ServiceError> {
        self.gate
            .read(actor, "run_alert_automation", &ALERT_AUTOMATION_RUN, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query!(
                        r#"WITH chosen AS (
                               SELECT DISTINCT r.root_id
                               FROM queue.actions a
                               JOIN queue.action_roots r ON r.action_id = a.id
                               JOIN analysis.roots o ON o.id = r.root_id
                               WHERE a.kind = 'remediation_check' AND a.result = 'CONFIRMED' AND a.handler = $1
                                 AND a.updated_at >= now() - make_interval(hours => $2)
                                 AND ($3::uuid IS NULL OR r.root_id > $3)
                                 AND o.alerted_at IS NOT NULL AND o.owner_id IS NULL
                                 AND (o.disposition IS NULL OR o.disposition = 'OPEN')
                                 AND NOT EXISTS (
                                     SELECT FROM analysis.alert_automation_runs x
                                     WHERE x.rule_name = $4 AND x.mode = $5 AND x.root_id = r.root_id)
                               ORDER BY r.root_id LIMIT $6)
                           SELECT r.root_id, a.id, a.observable_type, a.observable_value, a.updated_at
                           FROM chosen c
                           JOIN queue.action_roots r ON r.root_id = c.root_id
                           JOIN queue.actions a ON a.id = r.action_id
                           WHERE a.kind = 'remediation_check' AND a.result = 'CONFIRMED' AND a.handler = $1
                             AND a.updated_at >= now() - make_interval(hours => $2)
                           ORDER BY r.root_id, a.id"#,
                        rule.trigger.probe,
                        rule.trigger.max_age_hours,
                        after,
                        rule.name,
                        rule.mode.as_str(),
                        limit,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut items: Vec<Item> = Vec::new();
                    for row in rows {
                        let confirmation = Confirmation {
                            check_id: row.id,
                            observable_type: row.observable_type,
                            observable_value: row.observable_value,
                            confirmed_at: row.updated_at,
                        };
                        match items.last_mut() {
                            Some(item) if item.root == row.root_id => {
                                item.evidence.confirmations.push(confirmation);
                            }
                            _ => items.push(Item {
                                root: row.root_id,
                                evidence: Evidence {
                                    probe: rule.trigger.probe.clone(),
                                    confirmations: vec![confirmation],
                                },
                                run: None,
                            }),
                        }
                    }
                    Ok(items)
                })
            })
            .await
    }

    /// The alert's next unfinished action, in `tx`, with its record on the run and the audit row: the
    /// guards and the run's claim first, under the alert's and the run's row locks.
    async fn act_in(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        rule: &Rule,
        item: &Item,
    ) -> Result<Audited<Stepped>, ServiceError> {
        let alert = sqlx::query!(
            "SELECT disposition, owner_id FROM analysis.roots
             WHERE id = $1 AND alerted_at IS NOT NULL FOR UPDATE",
            item.root,
        )
        .fetch_optional(tx.conn())
        .await?;
        let pending = item.run.is_some();
        let Some(alert) = alert else {
            return Ok(Audited::unchanged(Stepped::LeftAlone {
                reason: "the alert does not exist".to_owned(),
                pending,
            }));
        };
        let (run, before, new) = match &item.run {
            None => {
                if let Some(reason) =
                    left_alone_because(alert.disposition.as_deref(), alert.owner_id, false)
                {
                    return Ok(Audited::unchanged(Stepped::LeftAlone { reason, pending }));
                }
                let records: Vec<ActionRecord> = rule
                    .actions
                    .iter()
                    .map(|a| ActionRecord::pending(a.type_name()))
                    .collect();
                let inserted = sqlx::query_scalar!(
                    "INSERT INTO analysis.alert_automation_runs
                         (rule_name, root_id, mode, evidence, actions)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT ON CONSTRAINT alert_automation_runs_once DO NOTHING
                     RETURNING id",
                    rule.name,
                    item.root,
                    rule.mode.as_str(),
                    Json(&item.evidence) as _,
                    Json(&records) as _,
                )
                .fetch_optional(tx.conn())
                .await?;
                let Some(id) = inserted else {
                    // the unique key is the backstop against two sweeps
                    return Ok(Audited::unchanged(Stepped::LeftAlone {
                        reason: "another sweep has a run on the alert".to_owned(),
                        pending,
                    }));
                };
                (ReadRun { id, version: 1 }, records, true)
            }
            Some(read) => {
                let Some(records) = claimed(tx, read).await? else {
                    return Ok(Audited::unchanged(Stepped::LeftAlone {
                        reason: "another sweep has its run, or changed it since this one read it"
                            .to_owned(),
                        pending,
                    }));
                };
                let started = records.iter().any(|r| r.status.finished());
                if let Some(reason) =
                    left_alone_because(alert.disposition.as_deref(), alert.owner_id, started)
                {
                    return Ok(Audited::unchanged(Stepped::LeftAlone { reason, pending }));
                }
                let recorded: Vec<String> = records.iter().map(|r| r.kind.clone()).collect();
                if recorded != rule.action_types() {
                    // the rule was edited after the run started: which of its actions are done isn't known
                    save(tx, read, &records, RunStatus::Failed).await?;
                    let change = Change::updated(
                        Target::root(item.root),
                        &record(read.id, rule, RunStatus::Pending, &records),
                        &record(read.id, rule, RunStatus::Failed, &records),
                    )?
                    .details(&StepRecord {
                        action: None,
                        disposition_before: None,
                        remediations: &[],
                        reason: Some("the rule's actions changed"),
                    })?;
                    return Ok(Audited::changed(Stepped::Mismatched { recorded }, change));
                }
                (read.clone(), records, false)
            }
        };
        let Some(index) = before.iter().position(|r| !r.status.finished()) else {
            // every action is finished: the run is done, as a sweep that died before saving so would leave it
            let version = save(tx, &run, &before, RunStatus::Done).await?;
            let change = Change::updated(
                Target::root(item.root),
                &record(run.id, rule, RunStatus::Pending, &before),
                &record(run.id, rule, RunStatus::Done, &before),
            )?;
            return Ok(Audited::changed(
                Stepped::Finished {
                    action: String::new(),
                    status: ActionStatus::Done,
                    detail: Detail::default(),
                    reason: None,
                    run: ReadRun {
                        id: run.id,
                        version,
                    },
                    run_status: RunStatus::Done,
                    new,
                },
                change,
            ));
        };
        let action = &rule.actions[index];
        let mut remediations = Vec::new();
        let outcome = match action {
            Action::Disposition {
                disposition,
                comment,
            } => {
                let comment = comment.as_ref().map(|t| {
                    crate::observable_comments::normalize_comment(&t.render(
                        &rule.name,
                        item.root,
                        &item.evidence,
                    ))
                });
                let detail = Detail {
                    disposition: Some(disposition.clone()),
                    comment: comment.clone(),
                    ..Detail::default()
                };
                let now_open = alert.disposition.as_deref().is_none_or(|d| d == OPEN);
                if !now_open {
                    Outcome::Deferred(format!(
                        "the alert's disposition is now {}",
                        alert.disposition.as_deref().unwrap_or_default()
                    ))
                } else if !still_holds(tx, &rule.trigger, item.root).await? {
                    Outcome::Deferred("the trigger no longer holds".to_owned())
                } else {
                    if rule.mode == Mode::Enforce {
                        // the alert's lock is held, so what the guards read is what this replaces
                        self.disposition_in(
                            tx,
                            item.root,
                            disposition,
                            actor,
                            comment.as_deref(),
                            None,
                        )
                        .await?;
                    }
                    Outcome::Done(detail, None)
                }
            }
            Action::Comment { comment } => {
                let comment = crate::observable_comments::normalize_comment(&comment.render(
                    &rule.name,
                    item.root,
                    &item.evidence,
                ));
                if rule.mode == Mode::Enforce {
                    // ACE's own comment, with no author, as ace3 writes it as its automation user
                    let comment = crate::observable_comments::checked(&comment)?;
                    crate::alert_comments::insert_comments(
                        tx.conn(),
                        None,
                        actor,
                        &[item.root],
                        &comment,
                    )
                    .await?;
                }
                Outcome::Done(
                    Detail {
                        comment: Some(comment),
                        ..Detail::default()
                    },
                    None,
                )
            }
            Action::Remediate { targets } => {
                self.remediate_in(tx, actor, rule, item, *targets, &mut remediations)
                    .await?
            }
        };
        let mut records = before.clone();
        let (detail, status, reason) = match outcome {
            Outcome::Deferred(reason) => {
                let started = before.iter().any(|r| r.status.finished());
                if started {
                    return Ok(Audited::unchanged(Stepped::Deferred {
                        action: action.type_name().to_owned(),
                        reason,
                        kept: true,
                    }));
                }
                // nothing was done, so the run goes, and the rule considers the alert again later
                sqlx::query!(
                    "DELETE FROM analysis.alert_automation_runs WHERE id = $1",
                    run.id
                )
                .execute(tx.conn())
                .await?;
                let deferred = Stepped::Deferred {
                    action: action.type_name().to_owned(),
                    reason,
                    kept: false,
                };
                if new {
                    return Ok(Audited::unchanged(deferred));
                }
                let change = Change::removed(
                    Target::root(item.root),
                    &record(run.id, rule, RunStatus::Pending, &before),
                )?;
                return Ok(Audited::changed(deferred, change));
            }
            Outcome::Done(detail, None) => (detail, ActionStatus::Done, None),
            Outcome::Done(detail, Some(reason)) => (detail, ActionStatus::Skipped, Some(reason)),
        };
        let entry = &mut records[index];
        entry.attempts += 1;
        entry.status = status;
        entry.detail = detail.clone();
        entry.reason = reason.clone();
        let run_status = if records.iter().all(|r| r.status.finished()) {
            RunStatus::Done
        } else {
            RunStatus::Pending
        };
        let version = save(tx, &run, &records, run_status).await?;
        let after = record(run.id, rule, run_status, &records);
        let change = if new {
            Change::added(Target::root(item.root), &after)?
        } else {
            Change::updated(
                Target::root(item.root),
                &record(run.id, rule, RunStatus::Pending, &before),
                &after,
            )?
        }
        .details(&StepRecord {
            action: Some(action.type_name()),
            disposition_before: match action {
                Action::Disposition { .. } => Some(alert.disposition.as_deref().unwrap_or(OPEN)),
                _ => None,
            },
            remediations: &remediations,
            reason: None,
        })?;
        Ok(Audited::changed(
            Stepped::Finished {
                action: action.type_name().to_owned(),
                status,
                detail,
                reason,
                run: ReadRun {
                    id: run.id,
                    version,
                },
                run_status,
                new,
            },
            change,
        ))
    }

    /// The `remediate` action, in `tx`: its targets, those covered, and in enforce the removals it queues,
    /// whose ids go in `queued`.
    async fn remediate_in(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        rule: &Rule,
        item: &Item,
        targets: Targets,
        queued_ids: &mut Vec<i64>,
    ) -> Result<Outcome, ServiceError> {
        let evidence: BTreeSet<(String, String)> = item
            .evidence
            .confirmations
            .iter()
            .map(|c| (c.observable_type.clone(), c.observable_value.to_lowercase()))
            .collect();
        let observables: Vec<(String, String)> = match targets {
            Targets::Evidence => {
                let (kinds, values): (Vec<String>, Vec<String>) = evidence.iter().cloned().unzip();
                sqlx::query!(
                    r#"SELECT o.type AS "kind!", o.value AS "value!" FROM analysis.observables o
                       JOIN unnest($2::text[], $3::text[]) AS e (kind, value)
                         ON o.type = e.kind AND lower(o.value) = e.value
                       WHERE o.root_id = $1
                       ORDER BY o.type, o.value LIMIT $4"#,
                    item.root,
                    &kinds,
                    &values,
                    MAX_REMEDIATE_OBSERVABLES + 1,
                )
                .fetch_all(tx.conn())
                .await?
                .into_iter()
                .map(|row| (row.kind, row.value))
                .collect()
            }
            Targets::SameMessage => {
                let ids: BTreeSet<String> = evidence
                    .iter()
                    .filter(|(kind, _)| is_delivery(kind))
                    .filter_map(|(_, value)| message_id(value))
                    .collect();
                sqlx::query!(
                    r#"SELECT type AS "kind!", value AS "value!" FROM analysis.observables
                       WHERE root_id = $1 AND type = ANY($2)
                       ORDER BY type, value LIMIT $3"#,
                    item.root,
                    &delivery_types(),
                    MAX_REMEDIATE_OBSERVABLES + 1,
                )
                .fetch_all(tx.conn())
                .await?
                .into_iter()
                .map(|row| (row.kind, row.value))
                .filter(|(_, value)| message_id(value).is_some_and(|id| ids.contains(&id)))
                .collect()
            }
        };
        if observables.len() as i64 > MAX_REMEDIATE_OBSERVABLES {
            return Err(ServiceError::TooLarge(format!(
                "the alert has more than {MAX_REMEDIATE_OBSERVABLES} observables to remediate"
            )));
        }
        if observables.is_empty() {
            return Ok(Outcome::Done(
                Detail::default(),
                Some("the alert has no observable to remediate".to_owned()),
            ));
        }
        let mut targets: Vec<(&'static str, String, String)> = Vec::new();
        let mut untargeted = Vec::new();
        for (kind, value) in &observables {
            let before = targets.len();
            for spec in self.actions.of_kind(ActionKind::Remediation) {
                if spec.observable_type == kind {
                    let target = (spec.name, kind.clone(), value.clone());
                    if !targets.contains(&target) {
                        targets.push(target);
                    }
                }
            }
            if targets.len() == before {
                untargeted.push(format!("{kind}:{value}"));
            }
        }
        let requested_by = serde_json::to_value(actor)?;
        let (mut queued, mut covered) = (Vec::new(), Vec::new());
        for (remediator, kind, value) in &targets {
            let name = format!("{remediator}:{kind}:{value}");
            if core_actions::removal_covers(&mut *tx.conn(), remediator, kind, value).await? {
                covered.push(name);
                continue;
            }
            if rule.mode == Mode::Enforce {
                queued_ids.push(
                    core_actions::queue_remediation(
                        tx,
                        &self.actions,
                        &NewRemediation {
                            handler: remediator,
                            observable_type: kind,
                            observable_value: value,
                            action: RemediationAction::Remove,
                            restore_key: None,
                            requested_by: &requested_by,
                            user: None,
                        },
                    )
                    .await?,
                );
            }
            queued.push(name);
        }
        Ok(Outcome::Done(
            Detail {
                queued: Some(queued),
                covered: Some(covered),
                untargeted: Some(untargeted),
                ..Detail::default()
            },
            None,
        ))
    }
}

/// Where a rule's sweep is.
#[derive(Debug, Clone, Copy)]
enum Pages {
    Pending { after: i64 },
    Candidates { after: Option<Uuid> },
    Done,
}

/// What an action came to, before it's recorded: done (with a reason, skipped) or deferred.
enum Outcome {
    Done(Detail, Option<String>),
    Deferred(String),
}

fn record<'a>(
    id: i64,
    rule: &'a Rule,
    status: RunStatus,
    actions: &'a [ActionRecord],
) -> RunRecord<'a> {
    RunRecord {
        run: id,
        rule: &rule.name,
        mode: rule.mode.as_str(),
        status: status.as_str(),
        actions,
    }
}

/// The run's records, locked for this sweep, or None when another sweep holds its lock, changed it since
/// `read`, or finished it.
async fn claimed(
    tx: &mut Tx<'_>,
    read: &ReadRun,
) -> Result<Option<Vec<ActionRecord>>, ServiceError> {
    let row = sqlx::query!(
        r#"SELECT status, version, actions AS "actions: Json<Vec<ActionRecord>>"
           FROM analysis.alert_automation_runs WHERE id = $1 FOR UPDATE SKIP LOCKED"#,
        read.id,
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(row
        .filter(|row| {
            row.version == read.version && RunStatus::parse(&row.status) == RunStatus::Pending
        })
        .map(|row| row.actions.0))
}

/// Writes the run's records and status, and returns its new version.
async fn save(
    tx: &mut Tx<'_>,
    run: &ReadRun,
    actions: &[ActionRecord],
    status: RunStatus,
) -> Result<i32, ServiceError> {
    Ok(sqlx::query_scalar!(
        "UPDATE analysis.alert_automation_runs
         SET actions = $2, status = $3, version = version + 1, updated_at = now()
         WHERE id = $1
         RETURNING version",
        run.id,
        Json(actions) as _,
        status.as_str(),
    )
    .fetch_one(tx.conn())
    .await?)
}

/// Whether the trigger holds for the alert now: ace3's `still_holds`, read under the alert's lock.
async fn still_holds(tx: &mut Tx<'_>, trigger: &Trigger, root: Uuid) -> Result<bool, ServiceError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (
               SELECT FROM queue.actions a
               JOIN queue.action_roots r ON r.action_id = a.id AND r.root_id = $3
               WHERE a.kind = 'remediation_check' AND a.result = 'CONFIRMED' AND a.handler = $1
                 AND a.updated_at >= now() - make_interval(hours => $2)) AS "holds!""#,
        trigger.probe,
        trigger.max_age_hours,
        root,
    )
    .fetch_one(tx.conn())
    .await?)
}

/// Counts a failed action on its run, in `tx`: a new run is recorded with it, and the action that ran
/// out of attempts fails with its run.
async fn failed_in(
    tx: &mut Tx<'_>,
    rule: &Rule,
    item: &Item,
    reason: &str,
    max_attempts: u32,
) -> Result<Audited<Stepped>, ServiceError> {
    let reason = core_actions::bounded(reason);
    let pending = item.run.is_some();
    let (run, before, new) = match &item.run {
        None => {
            let records: Vec<ActionRecord> = rule
                .actions
                .iter()
                .map(|a| ActionRecord::pending(a.type_name()))
                .collect();
            let inserted = sqlx::query_scalar!(
                "INSERT INTO analysis.alert_automation_runs (rule_name, root_id, mode, evidence, actions)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT ON CONSTRAINT alert_automation_runs_once DO NOTHING
                 RETURNING id",
                rule.name,
                item.root,
                rule.mode.as_str(),
                Json(&item.evidence) as _,
                Json(&records) as _,
            )
            .fetch_optional(tx.conn())
            .await?;
            let Some(id) = inserted else {
                return Ok(Audited::unchanged(Stepped::LeftAlone {
                    reason: "another sweep has a run on the alert".to_owned(),
                    pending,
                }));
            };
            (ReadRun { id, version: 1 }, records, true)
        }
        Some(read) => match claimed(tx, read).await? {
            Some(records) => (read.clone(), records, false),
            None => {
                return Ok(Audited::unchanged(Stepped::LeftAlone {
                    reason: "another sweep has its run, or changed it since this one read it"
                        .to_owned(),
                    pending,
                }));
            }
        },
    };
    let Some(index) = before.iter().position(|r| !r.status.finished()) else {
        return Ok(Audited::unchanged(Stepped::LeftAlone {
            reason: "every action of its run is finished".to_owned(),
            pending,
        }));
    };
    let mut records = before.clone();
    let entry = &mut records[index];
    entry.attempts += 1;
    entry.reason = Some(reason.clone());
    let gave_up = entry.attempts >= max_attempts;
    let status = if gave_up {
        entry.status = ActionStatus::Failed;
        RunStatus::Failed
    } else {
        RunStatus::Pending
    };
    let attempts = entry.attempts;
    let action = entry.kind.clone();
    save(tx, &run, &records, status).await?;
    let after = record(run.id, rule, status, &records);
    let change = if new {
        Change::added(Target::root(item.root), &after)?
    } else {
        Change::updated(
            Target::root(item.root),
            &record(run.id, rule, RunStatus::Pending, &before),
            &after,
        )?
    }
    .details(&StepRecord {
        action: Some(&action),
        disposition_before: None,
        remediations: &[],
        reason: Some(&reason),
    })?;
    Ok(Audited::changed(
        Stepped::Counted {
            action,
            attempts,
            gave_up,
            new,
        },
        change,
    ))
}

/// Logs what a step did, counts it, and returns the step that follows it on the same alert, if any. A
/// refusal of the sweep's permission ends the sweep.
fn next_step<'r>(
    sweep: &mut AutomationSweep,
    step: &Step<'r>,
    written: Result<Stepped, ServiceError>,
    max_attempts: u32,
) -> Result<Option<Step<'r>>, ServiceError> {
    let (rule, item) = match step {
        Step::Act { rule, item } | Step::Failed { rule, item, .. } => (*rule, item),
    };
    let alert_uuid = item.root;
    let (rule_name, mode) = (rule.name.as_str(), rule.mode.as_str());
    match written {
        Err(error @ ServiceError::PermissionDenied { .. }) => Err(error),
        Err(error) => match step {
            Step::Act { .. } => {
                // the action and its record rolled back; the failure is counted, and logged with its
                // attempt, in a transaction of its own
                sweep.actions_failed += 1;
                Ok(Some(Step::Failed {
                    rule,
                    item: item.clone(),
                    reason: error.to_string(),
                }))
            }
            Step::Failed { reason, .. } => {
                tracing::error!(
                    rule = rule_name, alert_uuid = %alert_uuid, mode,
                    "alert automation rule {rule_name} failed on alert {alert_uuid} ({reason}), and the failure \
                     couldn't be recorded; the alert is considered again on the next sweep: {error}"
                );
                sweep.unrecorded += 1;
                sweep.first_error.get_or_insert_with(|| error.to_string());
                Ok(None)
            }
        },
        Ok(Stepped::Finished {
            action,
            status,
            detail,
            reason,
            run,
            run_status,
            new,
        }) => {
            if new {
                sweep.runs_started += 1;
            }
            if !action.is_empty() {
                sweep.actions_finished += 1;
                tracing::info!(
                    rule = rule_name, alert_uuid = %alert_uuid, action, mode, status = status.as_str(),
                    detail = %serde_json::to_string(&detail).unwrap_or_default(),
                    reason = reason.as_deref().unwrap_or(""),
                    "alert automation rule {rule_name}: action {action} {} on alert {alert_uuid} ({mode})",
                    status.as_str()
                );
                for observable in detail.untargeted.iter().flatten() {
                    let kind = observable
                        .split_once(':')
                        .map_or(observable.as_str(), |(k, _)| k);
                    tracing::error!(
                        rule = rule_name, alert_uuid = %alert_uuid, action, mode, observable,
                        "alert automation rule {rule_name}: no remediation target for {observable} in alert \
                         {alert_uuid}, so ACE can't remove it; check the remediators for {kind}"
                    );
                }
            }
            if run_status == RunStatus::Pending {
                return Ok(Some(Step::Act {
                    rule,
                    item: Item {
                        run: Some(run),
                        ..item.clone()
                    },
                }));
            }
            Ok(None)
        }
        Ok(Stepped::Deferred {
            action,
            reason,
            kept,
        }) => {
            sweep.actions_deferred += 1;
            tracing::info!(
                rule = rule_name, alert_uuid = %alert_uuid, action, mode, reason, kept,
                "alert automation rule {rule_name}: action {action} left alert {alert_uuid} alone: {reason}"
            );
            Ok(None)
        }
        Ok(Stepped::LeftAlone { reason, pending }) => {
            if pending {
                // retried on every sweep until the guard lets it through
                sweep.left_alone += 1;
                tracing::info!(
                    rule = rule_name, alert_uuid = %alert_uuid, mode, reason,
                    "alert automation rule {rule_name} leaves alert {alert_uuid} alone: {reason}"
                );
            } else {
                tracing::debug!(
                    rule = rule_name, alert_uuid = %alert_uuid, mode, reason,
                    "alert automation rule {rule_name} leaves alert {alert_uuid} alone: {reason}"
                );
            }
            Ok(None)
        }
        Ok(Stepped::Mismatched { recorded }) => {
            sweep.runs_failed += 1;
            tracing::error!(
                rule = rule_name, alert_uuid = %alert_uuid, mode,
                "alert automation rule {rule_name}: its actions are now {}, but its run on alert {alert_uuid} \
                 was started for {}; the run is marked failed and nothing more runs",
                rule.action_types().join(", "),
                recorded.join(", ")
            );
            Ok(None)
        }
        Ok(Stepped::Counted {
            action,
            attempts,
            gave_up,
            new,
        }) => {
            if new {
                sweep.runs_started += 1;
            }
            let reason = match step {
                Step::Failed { reason, .. } => reason.as_str(),
                Step::Act { .. } => "",
            };
            let gave_up_text = if gave_up {
                sweep.runs_failed += 1;
                format!(
                    "; gave up after {attempts} attempts, and the rule's later actions do not run"
                )
            } else {
                String::new()
            };
            tracing::error!(
                rule = rule_name, alert_uuid = %alert_uuid, action, mode, attempt = attempts, gave_up,
                "alert automation rule {rule_name}: action {action} failed on alert {alert_uuid} (attempt \
                 {attempts} of {max_attempts}): {reason}{gave_up_text}"
            );
            Ok(None)
        }
    }
}
