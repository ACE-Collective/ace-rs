//! `mailbox_email_analyzer`, a port of ace3's `MailboxEmailAnalyzer` (`saq/modules/email/mailbox.py`).
//!
//! For a root of alert type `mailbox` only, on the email with the `original_email` directive: names
//! the root `ACE Mailbox Scanner Detection - <subject>`, merges the email's analysis into the root's
//! details, and adds `tracked` to the Message-IDs the email's analysis added. ace3 changes the root
//! itself; here the result carries the changes (`ResultEnvelope::root`, `Module::SETS_ROOT`) and the
//! directive (`ResultEnvelope::others`), which the core lands with it.

use ace_results::types::email::EmailAnalysis;
use ace_results::types::emailtree::MailboxEmailAnalysis;
use ace_results::{
    AnalysisType, ObservableAdditions, ObservableKind, OtherAdditions, ResultEnvelope, RootChanges,
};
use ace_sdk::{Manifest, Module, ModuleError, OtherAdditionsAllowed, Outcome, Parser, TaskContext};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<MailboxEmailAnalyzer>();

/// The alert type ace3's mailbox collector gives the roots it submits.
pub const MAILBOX: &str = "mailbox";
pub const MAILBOX_ALERT_PREFIX: &str = "ACE Mailbox Scanner Detection -";
pub const ORIGINAL_EMAIL: &str = "original_email";
pub const TRACKED: &str = "tracked";

/// The mailbox module.
pub struct MailboxEmailAnalyzer;

impl Module for MailboxEmailAnalyzer {
    const NAME: &'static str = "mailbox_email_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[EmailAnalysis::MODULE];
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[ORIGINAL_EMAIL];
    const READS_TREE: bool = true;
    const ADDS_TO_OTHERS: Option<OtherAdditionsAllowed> = Some(OtherAdditionsAllowed {
        tags: &[],
        directives: &[TRACKED],
        detections: false,
    });
    const SETS_ROOT: bool = true;
    type Output = MailboxEmailAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(MailboxEmailAnalyzer)
    }
}

impl Parser for MailboxEmailAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<MailboxEmailAnalysis>, ModuleError> {
        let tree = ctx
            .tree()
            .ok_or_else(|| ModuleError::other("the task came without its root's tree"))?;
        if tree.alert_type.as_deref() != Some(MAILBOX) {
            return Ok(Outcome::Skipped("not a mailbox alert".to_owned()));
        }
        let email = ctx
            .dependency_result::<EmailAnalysis>()?
            .filter(|email| !email.is_tag_only());
        let mut result = ResultEnvelope::new(MailboxEmailAnalysis {});
        let Some(email) = email else {
            result.root = Some(RootChanges {
                description: Some(format!("{MAILBOX_ALERT_PREFIX} unparsable email")),
                details: None,
            });
            return Ok(Outcome::Done(result));
        };
        let details = email.email.as_ref();
        let subject = details
            .and_then(|d| d.decoded_subject.as_deref())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                details
                    .and_then(|d| d.subject.as_deref())
                    .filter(|s| !s.is_empty())
            });
        let description = match subject {
            Some(subject) => format!("{MAILBOX_ALERT_PREFIX} {subject}"),
            None => format!("{MAILBOX_ALERT_PREFIX} (no subject)"),
        };
        let merged = match serde_json::to_value(&email) {
            Ok(serde_json::Value::Object(map)) => map,
            Ok(_) => serde_json::Map::new(),
            Err(e) => return Err(ModuleError::other(format!("the email's analysis: {e}"))),
        };
        result.root = Some(RootChanges {
            description: Some(description),
            details: Some(merged),
        });
        // the Message-IDs the email's analysis added are tracked across analysis
        let email_results = tree
            .results_on(tree.this)
            .filter(|r| r.analysis_type == EmailAnalysis::NAME);
        for added in email_results.flat_map(|r| &r.added) {
            let observable = tree.observable(added.observable);
            if observable.kind != ObservableKind::MessageId
                || result
                    .others
                    .iter()
                    .any(|o| o.observable.value == observable.value)
            {
                continue;
            }
            let mut additions = ObservableAdditions::default();
            additions.add_directive(TRACKED);
            result.others.push(OtherAdditions {
                observable: observable.reference(),
                additions,
            });
        }
        Ok(Outcome::Done(result))
    }
}
